rule Virus_Hijack_Gen_Variant_Packy_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Packy.4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "896895bec8678f64a9e1e0df17d0be62e6ce7920842d78b6dfc8457c862474f3"

  strings:
    $s1 = "akinesia" fullword wide
    $s2 = "Roundwood" fullword wide
    $s3 = "Grison" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}