rule SUSP_ntdlldll_mutation_decimal {
  meta:
    author      = "Greg Lesnewich"
    description = "track string mutations of ntdll.dll which can be used for syscalls"
    date        = "2024-01-23"
    version     = "1.0"
    DaysofYARA  = "24/100"

  strings:
    $ntdlldll_decimal = "110 116 100 108 108 46 100 108 108" ascii wide nocase

  condition:
    all of them
}