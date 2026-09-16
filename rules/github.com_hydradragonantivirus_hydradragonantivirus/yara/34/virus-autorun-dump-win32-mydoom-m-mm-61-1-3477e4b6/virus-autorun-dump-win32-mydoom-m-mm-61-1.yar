rule Virus_Autorun_Dump_Win32_Mydoom_M_mm_61_1 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Dump.Win32.Mydoom.M@mm_61_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b33533743d87723ffd1a112b653797b4b9e35f99f06580ea0a029d292b4d60c"

  strings:
    $s1 = "System Information.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}