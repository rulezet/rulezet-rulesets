rule Virus_Hijack_Gen_Variant_Midie_131130 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Midie.131130.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8406d3313b1f0b681c9ebe73c638d5284bbb06c1791dc26a50a03d367250e5f"

  strings:
    $s1 = "ramiferous" fullword wide
    $s2 = "Tattooment" fullword wide
    $s3 = "Gnathonize" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}