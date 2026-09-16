rule Virus_Infector_Gen_Variant_Ransom_TeslaCrypt_89_8 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Gen.Variant.Ransom.TeslaCrypt.89_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a77191d8d2bacfaa83426e7bbb706da3392668cba68d8c5540c944f7f56f502"

  strings:
    $s1 = "!This program cannot be rGXBCD" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}