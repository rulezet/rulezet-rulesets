rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_29_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_29_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a785237adb9b194dab84a783bfaeb5287c987e6919167b20d6b72f2d03745aa"

  strings:
    $s1 = "ewhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}