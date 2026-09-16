rule Virus_Hijack_Gen_Variant_Midie_131130_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Midie.131130_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1552628c7b331b963edf0d9f88cd658bfa9d445a859358308223e63b5287fdaa"

  strings:
    $s1 = "ramiferous" fullword wide
    $s2 = "Tattooment" fullword wide
    $s3 = "Gnathonize" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}