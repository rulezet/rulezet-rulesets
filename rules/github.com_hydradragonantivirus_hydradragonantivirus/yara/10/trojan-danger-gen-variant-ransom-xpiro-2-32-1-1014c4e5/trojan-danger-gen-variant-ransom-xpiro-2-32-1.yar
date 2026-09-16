rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_32_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_32_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb4e58523663be40319d507d993438b31c7ca5962da1fafcbc8d398952832455"

  strings:
    $s1 = "Dive tastai cp esca" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}