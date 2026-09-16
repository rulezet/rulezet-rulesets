rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_66_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_66_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37f74a997c3b39e57b534183460f54302d80fe0529cd2518356516216df87d0d"

  strings:
    $s1 = "vCallbackListToRpc: begin" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}