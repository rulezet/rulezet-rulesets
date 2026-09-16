import "elf"
rule ESET_Libkeyutils_With_Ctor {
  meta:
    description = "This rule detects if a libkeyutils.so shared library has a potentially malicious function to be called when loaded, either via a glibc constructor (DT_INIT + .ctors) or an initializer function in DT_INIT_ARRAY."
    author      = "ESET, spol. s r.o."
    id          = "7b466bf7-f895-569d-99b0-eca95a6ebc83"
    date        = "2024-02-01"
    modified    = "2024-04-29"
    reference   = "https://github.com/eset/malware-ioc/"
    source_url  = "https://github.com/eset/malware-ioc/blob/21381c70ad030105cf9edb092dfd1cae29753286/windigo/ebury.yar#L3-L54"
    license_url = "https://github.com/eset/malware-ioc/blob/21381c70ad030105cf9edb092dfd1cae29753286/LICENSE"
    hash        = "e7debd6e453192ad8376db5bab03ed0d87566591"
    logic_hash  = "c6172aebc67a05fb044b0450aafcc71c7d1fd2831985587d1a9ad53f59e14214"
    score       = 75
    quality     = 80
    tags        = ""
    license     = "BSD 2-Clause"
    version     = 2

  strings:
    $libname = "libkeyutils.so.1"

  condition:
    for any ptr_size in (4, 8): (((ptr_size == 4 and elf.machine == elf.EM_386) or (ptr_size == 8 and elf.machine == elf.EM_X86_64)) and for any d in elf.dynamic: (d.type == elf.DT_SONAME and (for any s in elf.sections: (s.name == ".dynstr" and $libname at (s.offset + d.val)) or for any s in elf.dynamic: (s.type == elf.DT_STRTAB and $libname at (s.val + d.val)))) and (for any s in elf.sections: (s.name == ".ctors" and s.size > 2 * ptr_size) or for any d in elf.dynamic: (d.type == elf.DT_INIT_ARRAYSZ and d.val > ptr_size)))
}