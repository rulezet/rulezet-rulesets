rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_14_79 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.14_79.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "329a6f8a93a550f7bac8611b3c3ff080bea0271c22e05909c161b551b73f4e75"

  strings:
    $s1 = "n5orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}