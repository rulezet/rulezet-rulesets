rule Virus_Infector_Gen_Variant_Ransom_TeslaCrypt_89_10 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Gen.Variant.Ransom.TeslaCrypt.89_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bca0b96f407c5456b753d240cd1499271c0bccfb508392c1b4425fb16594f71c"

  strings:
    $s1 = "!This program cannot be rGXBCD" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}