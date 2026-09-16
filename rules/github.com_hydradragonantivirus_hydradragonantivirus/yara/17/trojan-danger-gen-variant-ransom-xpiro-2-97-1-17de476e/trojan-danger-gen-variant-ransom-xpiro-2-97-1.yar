rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_97_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_97_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "932e3dd512a74c139111371c6dcb4707e4d2e6c826c8bb5a4ed8079473cd92bf"

  strings:
    $s1 = "y`purchase orders transmitted from Oracle Purchasing, during a 12 month period. You may not exceed the licensed number of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}