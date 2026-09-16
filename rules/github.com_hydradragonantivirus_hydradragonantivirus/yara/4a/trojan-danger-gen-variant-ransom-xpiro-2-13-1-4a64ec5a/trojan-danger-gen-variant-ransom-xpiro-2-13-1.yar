rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_13_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29ece46c5eb4ec8a2f41f3af4a4ea2de8c604f4649a1b7f87dc0e60f8f49ff67"

  strings:
    $s1 = "zAmerica, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii
    $s2 = "Limited, East Point Business Park, Fairview, Dublin 3, Ireland," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}