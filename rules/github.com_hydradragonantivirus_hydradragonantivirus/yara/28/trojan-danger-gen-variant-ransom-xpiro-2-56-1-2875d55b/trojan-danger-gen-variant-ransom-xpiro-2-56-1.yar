rule Trojan_Danger_Gen_Variant_Ransom_Xpiro_2_56_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Gen.Variant.Ransom.Xpiro.2_56_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4b49c8397c829b0e58e74a5f843d74df961ae8a3a0009a827ba454cdaa99767"

  strings:
    $s1 = "z]Software Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}