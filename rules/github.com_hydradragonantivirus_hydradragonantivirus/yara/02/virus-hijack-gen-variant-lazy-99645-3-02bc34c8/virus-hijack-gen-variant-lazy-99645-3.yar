rule Virus_Hijack_Gen_Variant_Lazy_99645_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Variant.Lazy.99645_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20f23ef4c148d579b8cefeca753ed960ac0ec448a5cd0390f565616e11dfd2c3"

  strings:
    $s1 = "phototypist" fullword wide
    $s2 = "knopped" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}