rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_14_34_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.14_34_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7a390807e0bf54c860a8811c3f74f4290106a079dbc101063be9482919ba1bd"

  strings:
    $s1 = "`orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}