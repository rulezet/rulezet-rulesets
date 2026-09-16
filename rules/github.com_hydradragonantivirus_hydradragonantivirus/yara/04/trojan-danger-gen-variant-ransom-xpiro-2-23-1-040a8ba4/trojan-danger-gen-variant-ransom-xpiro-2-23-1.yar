rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_23_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_23_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "893243a7cff848c0867af4aff0f132a816bce009f1b5480317546c9668642a40"

  strings:
    $s1 = "[]&sKAg" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}