rule Virus_Hijack_Gen_Variant_Lazy_99645 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Lazy.99645.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f008697635a188b6e27356ee21e68fb5e9a172912e7313e2953ca3d7f0e0943e"

  strings:
    $s1 = "phototypist" fullword wide
    $s2 = "knopped" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}