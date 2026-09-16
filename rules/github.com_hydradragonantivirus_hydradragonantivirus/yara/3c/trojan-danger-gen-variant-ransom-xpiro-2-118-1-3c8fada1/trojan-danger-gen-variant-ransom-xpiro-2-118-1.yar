rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_118_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_118_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65d62f65a0139ee8c084e762025ef94c821c8c54f0635fc42c6b7babfa1b9aa7"

  strings:
    $s1 = ">orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}