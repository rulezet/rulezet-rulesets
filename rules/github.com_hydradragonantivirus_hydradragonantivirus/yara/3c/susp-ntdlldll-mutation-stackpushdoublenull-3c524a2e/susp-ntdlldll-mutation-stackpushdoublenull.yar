rule SUSP_ntdlldll_mutation_stackpushdoublenull {
  meta:
    author      = "Greg Lesnewich"
    description = "track string mutations of ntdll.dll which can be used for syscalls"
    date        = "2024-01-23"
    version     = "1.0"
    DaysofYARA  = "24/100"

  strings:
    $ntdlldll_stackpushdoublenull = "hl\x00\x00hl.dlhntdl" ascii wide nocase

  condition:
    all of them
}