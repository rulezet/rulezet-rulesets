rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_330_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_330_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "263703c672635c889b2efbff3ac2efcdcd3a4ed3ebf778a08ef336f3d5baf4f9"

  strings:
    $s1 = "@~~@Java Machine@~~@1@~~@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}