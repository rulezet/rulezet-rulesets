rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_232_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_232_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "45b28941f08328d6a74409826c62e0362d82fdf4ddd4149538ff6a713a420ce4"

  strings:
    $s1 = "7%poMe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}