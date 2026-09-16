rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_69_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_69_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5bec7b5c3d4e010985baa91896d4a9f1f3dd844121ca2cbe165a68cefb2dff93"

  strings:
    $s1 = "~dispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}