rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_334_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_334_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ffce7f39b434afae2ea845512413b0588fd0eb40bbb42fd56fd28f12ba2aa15"

  strings:
    $s1 = "@~~@Java Machine@~~@1@~~@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}