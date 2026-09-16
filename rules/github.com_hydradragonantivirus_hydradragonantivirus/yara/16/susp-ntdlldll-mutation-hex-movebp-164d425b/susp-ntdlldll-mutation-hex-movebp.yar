rule SUSP_ntdlldll_mutation_hex_movebp {
  meta:
    author      = "Greg Lesnewich"
    description = "track string mutations of ntdll.dll which can be used for syscalls"
    date        = "2024-01-23"
    version     = "1.0"
    DaysofYARA  = "24/100"

  strings:
    $ntdlldll_hex_movebp = { c6 45 ?? 6e c6 45 ?? 74 c6 45 ?? 64 c6 45 ?? 6c c6 45 ?? 6c c6 45 ?? 2e c6 45 ?? 64 c6 45 ?? 6c c6 45 ?? 6c }

  condition:
    all of them
}