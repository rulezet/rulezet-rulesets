rule Virus_Autorun_Win32_Neshta_A_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd11ea68e0a8474a7f069036051e9136fe96fb3d8f6192fc738b27365e5d6ed0"

  strings:
    $s1 = "Microsoft Office Diagnostics.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}