rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_306_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_306_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c847e1f389195478940520ab41870923f7a831ebc5bfe3c822adc3ca38b9fb99"

  strings:
    $s1 = "9 joLl" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}