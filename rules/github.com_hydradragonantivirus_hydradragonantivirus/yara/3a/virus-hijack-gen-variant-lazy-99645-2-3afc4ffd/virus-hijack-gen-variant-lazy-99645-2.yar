rule Virus_Hijack_Gen_Variant_Lazy_99645_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Lazy.99645_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a969f580474d6cdecbe997a55b4af97fd735c03f0b8b25e3ddc2cafd77ccfcd6"

  strings:
    $s1 = "phototypist" fullword wide
    $s2 = "knopped" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}