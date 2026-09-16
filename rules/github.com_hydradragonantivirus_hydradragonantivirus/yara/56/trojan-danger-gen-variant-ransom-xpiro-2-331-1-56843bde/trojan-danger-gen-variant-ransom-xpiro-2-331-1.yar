rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_331_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_331_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ede745b91a7f2ff41ce04766e5d743c39203d42fb6c9fea13617ca6bed6fb4ef"

  strings:
    $s1 = "@~~@Java Machine@~~@1@~~@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}