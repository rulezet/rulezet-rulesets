rule Virus_Hijack_Gen_Variant_Lazy_276804 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Lazy.276804.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "362d020dd98387dc84dc2f82f4aa5ec219893eee7490ac5e7ebf09649d6274d3"

  strings:
    $s1 = "leucoplakia" fullword wide
    $s2 = "8+6<FeEd" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}