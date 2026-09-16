rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_301_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_301_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7968a9ece1e0b137dbd45d6ec0faf328485c01612663d266486bdd7073de4ca3"

  strings:
    $s1 = "9software features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}