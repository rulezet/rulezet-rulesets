rule Virus_Hijack_Gen_Variant_Zusy_540557 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Zusy.540557.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d6f340e29851b51be1242ee212b2315b49d17e273dc9519f011fee50b5669e9"

  strings:
    $s1 = "LIte&T4" fullword ascii
    $s2 = "PUky[HJ" fullword ascii
    $s3 = "#qsD:Homo" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}