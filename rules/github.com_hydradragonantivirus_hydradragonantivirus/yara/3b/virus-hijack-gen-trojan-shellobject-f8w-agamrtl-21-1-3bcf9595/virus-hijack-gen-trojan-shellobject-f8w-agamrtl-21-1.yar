rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aGAMRTl_21_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aGAMRTl_21_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a121687578fcec7cc31494a21e91a41720a8ccec3c1054d4a70cbb19c936129"

  strings:
    $s1 = "Ac?Unknow" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}