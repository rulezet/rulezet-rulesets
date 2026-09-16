rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_298_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_298_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6db3ad24efb216a80df5dc49025d03d366904a80a4cf496810ec5efa3d520786"

  strings:
    $s1 = "Bsoftware features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}