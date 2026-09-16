rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_294_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_294_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40705efec68fafcc02c5a7aa3e662617b4fe879949c1d346cb17e0ee391824d3"

  strings:
    $s1 = ";software features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}