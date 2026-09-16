rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_91_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_91_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06875ac88e353d0810403c8dea3a5f255f9e16e3cb2c01e14b76c0a3969760a6"

  strings:
    $s1 = "%CUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}