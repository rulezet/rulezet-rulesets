rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_174_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_174_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c03aeb6cb9fe89cb4b61c1fae33534c5f89019a6d50fc897c0e622427c82630"

  strings:
    $s1 = "=WAmerica, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}