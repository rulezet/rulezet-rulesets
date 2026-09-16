rule Virus_Hijack_Gen_Trojan_ShellObject_m8Z_aGAMRTl_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8Z@aGAMRTl_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35c47f10f1e0f74681074bc8ab1648716d1e8a291b28bf8952fd9f8b8ad5b3fd"

  strings:
    $s1 = "t>cUiR" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}