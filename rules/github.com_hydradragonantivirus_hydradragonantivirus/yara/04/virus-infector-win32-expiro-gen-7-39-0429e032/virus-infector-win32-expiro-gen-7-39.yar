rule Virus_Infector_Win32_Expiro_Gen_7_39 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_39.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5875b7e78a19628bf3f2aba331d69f022aaa0bc28537e579af98d30b3ace7bb7"

  strings:
    $s1 = "miCO>@4" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}