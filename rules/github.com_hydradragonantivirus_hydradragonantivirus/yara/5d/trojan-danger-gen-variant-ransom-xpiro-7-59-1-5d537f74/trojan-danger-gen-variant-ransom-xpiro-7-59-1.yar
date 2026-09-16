rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_59_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_59_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e05c9eafe4a09f0564b2b060b61ea3ef91097a4631acc364195d229ff45e3c5"

  strings:
    $s1 = "software features to upgrade or fix the software and otherwise impr" fullword ascii
    $s2 = "wUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}