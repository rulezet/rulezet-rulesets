rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_266_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_266_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4cc5a47bd029360861b482064cc833c6f0a7f45d8e8105088db5ce888a3ce871"

  strings:
    $s1 = "SKwhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}