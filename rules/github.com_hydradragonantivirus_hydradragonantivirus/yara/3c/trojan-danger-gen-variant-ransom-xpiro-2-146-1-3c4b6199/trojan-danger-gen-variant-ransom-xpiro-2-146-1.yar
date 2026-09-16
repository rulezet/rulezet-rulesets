rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_146_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_146_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66e738609d38e2c5665799ef119a15a3a701b43ef2aeaed9911c16c8854d0b02"

  strings:
    $s1 = "9@whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}