rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_268_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_268_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d1a5e898a7fcb0dab8f36379eabc6b9c6caf50168042a35ad62e73fd5c7d56e"

  strings:
    $s1 = "{iorders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}