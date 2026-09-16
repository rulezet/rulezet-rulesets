import "elf"
rule _ApacheModule {
  meta:
    description   = "Apache 2.4 module ELF shared library"
    author        = "Marc-Etienne M.Léveillé <leveille@eset.com>"
    copyright     = "ESET, spol. s r.o."
    license       = "BSD 2-Clause"
    date          = "2024-04-27"
    reference     = "https://www.welivesecurity.com"
    source        = "https://github.com/eset/malware-ioc/"
    hash          = "e39667aa137e315bc26eaef791ccab52938fd809"
    version       = 1
    last_modified = "2024-04-27"

  strings:
    $magic = "42PA"  
  condition:
    for any s in elf.dynsym: (
      s.type == elf.STT_OBJECT and
      for any seg in elf.segments: (
        seg.type == elf.PT_LOAD and
        s.value >= seg.virtual_address and
        s.value < (seg.virtual_address + seg.file_size) and
        $magic at (s.value - seg.virtual_address + seg.offset) + 0x28
      )
    )
}