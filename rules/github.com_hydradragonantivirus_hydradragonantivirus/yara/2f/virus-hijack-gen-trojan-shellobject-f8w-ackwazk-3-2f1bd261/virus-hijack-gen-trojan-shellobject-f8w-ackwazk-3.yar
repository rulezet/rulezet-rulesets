rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aCkwazk_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aCkwazk_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06aa85da0ecd0b2eaeeed978bea85fde53a7ee674d1954d1dc98fc208eddfc6d"

  strings:
    $s1 = "-by different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}