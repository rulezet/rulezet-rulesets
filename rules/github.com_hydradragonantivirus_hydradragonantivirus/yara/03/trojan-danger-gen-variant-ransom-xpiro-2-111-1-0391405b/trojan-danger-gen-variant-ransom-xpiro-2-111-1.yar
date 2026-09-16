rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_111_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_111_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "69e2c035883b22dcb8d82b610af4b6e7245a86b3e6bdba40d144fecd95a30543"

  strings:
    $s1 = "^orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}