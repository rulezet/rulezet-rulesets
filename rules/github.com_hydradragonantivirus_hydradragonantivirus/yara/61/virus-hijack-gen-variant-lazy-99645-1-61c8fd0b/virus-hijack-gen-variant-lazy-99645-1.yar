rule Virus_Hijack_Gen_Variant_Lazy_99645_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Lazy.99645_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8bd8981e6046200cc3c0f41241f1d5076e0e6ae62c05fbb182ba93d50519b508"

  strings:
    $s1 = "phototypist" fullword wide
    $s2 = "knopped" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}