rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_7_101_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.7_101_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "befbf4131e72eccd2971d87158ea2c0dbe52ff41b747c84b9e9067cd2a04f5e5"

  strings:
    $s1 = "^}ekER]d_jezBRIxC|ocEXo" fullword ascii
    $s2 = "6\"Sant" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}