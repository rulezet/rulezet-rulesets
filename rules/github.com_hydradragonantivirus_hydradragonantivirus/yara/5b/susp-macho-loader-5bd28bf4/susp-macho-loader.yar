rule susp_macho_loader {
  meta:
    description = "Identify Mach-O excutables like the ObjCShellcodeLoader"
    author      = "@shellcromancer"
    version     = "1.0"
    date        = "2023.03.17"
    reference   = "https://github.com/slyd0g/ObjCShellcodeLoader/tree/main"
    sample      = "0ca96a9647a3506aeda50c9f6df3d173098b80c81937777af245da768867a4c9"
    DaysofYARA  = "76/100"

  strings:
    $s1 = "mach_vm_write failed to write shellcode"
    $s2 = "_mach_vm_allocate"
    $s3 = "_mach_vm_protect"
    $s4 = "_mach_vm_write"

  condition:
    (
      uint32(0) == 0xfeedface or        uint32(0) == 0xcefaedfe or        uint32(0) == 0xfeedfacf or        uint32(0) == 0xcffaedfe or        uint32(0) == 0xcafebabe or        uint32(0) == 0xbebafeca      ) and
    3 of them
}