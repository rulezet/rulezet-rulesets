rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_207_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_207_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cad9ebd615283cb39a5c89e1edc8aa97c686b0ceee685264ead1b278fedfc317"

  strings:
    $s1 = "Gwhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}