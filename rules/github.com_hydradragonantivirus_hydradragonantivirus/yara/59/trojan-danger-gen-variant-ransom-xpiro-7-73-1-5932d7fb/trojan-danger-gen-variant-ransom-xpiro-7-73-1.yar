rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_73_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_73_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c85856d549e03ded5c3844a8207ac57c867dd39ba402bbd791c43957fa8af06"

  strings:
    $s1 = "access the documentation online at http://oracle.com/contracts. Se" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}