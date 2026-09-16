rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_316_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_316_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30c06e68ec8bfa56ff2d57fd3bb2248c19b2c0d758c2911682b2289fa9efe995"

  strings:
    $s1 = "TaVe?`?gWaW3" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}