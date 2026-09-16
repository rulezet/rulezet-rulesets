rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aCkwazk_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aCkwazk_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "005d7ce5cac9441f73380e2518f3486473fe6180da39d49c33eb4a185c5e66c5"

  strings:
    $s1 = "PRby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}