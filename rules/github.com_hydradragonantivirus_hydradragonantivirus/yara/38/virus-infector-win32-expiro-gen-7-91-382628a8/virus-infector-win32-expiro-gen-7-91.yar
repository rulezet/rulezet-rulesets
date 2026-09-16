rule Virus_Infector_Win32_Expiro_Gen_7_91 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_91.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8eafeb6b9a3143ad112c3a8b4bfb96f2ab005415f578360ae0e9874a79f62622"

  strings:
    $s1 = "]sOle:^" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}