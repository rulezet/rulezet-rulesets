rule Virus_Hijack_Gen_Variant_Lazy_276804_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Lazy.276804_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "548aaf6bafeb976d1f8ccc3d7295696901056225bd9b09084407b9b3a8ce2ac1"

  strings:
    $s1 = "leucoplakia" fullword wide
    $s2 = "8+6<FeEd" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}