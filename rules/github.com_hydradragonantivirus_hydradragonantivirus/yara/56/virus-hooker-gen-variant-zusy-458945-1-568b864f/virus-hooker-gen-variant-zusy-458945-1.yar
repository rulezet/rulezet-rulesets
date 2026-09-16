rule Virus_Hooker_Gen_Variant_Zusy_458945_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hooker_Gen.Variant.Zusy.458945_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d508f7fa982b0d4f17cbc46379a901f91b90a438c93319e29afd995a079b1849"

  strings:
    $s1 = "C%mAZE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}