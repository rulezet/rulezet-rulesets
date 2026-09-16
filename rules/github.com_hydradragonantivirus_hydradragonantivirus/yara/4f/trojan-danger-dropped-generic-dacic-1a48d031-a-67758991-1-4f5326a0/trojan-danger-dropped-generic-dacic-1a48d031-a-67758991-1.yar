rule Trojan_Danger_Dropped_Generic_Dacic_1A48D031_A_67758991_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Dropped.Generic.Dacic.1A48D031.A.67758991_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f55f7809db60bff3a00ace0bcfa3aec0c16a8fae23a0fda991b9dc2cc8f4f21"

  strings:
    $s1 = "PROCESSOR_IDENTIFIER=Intel64 Family 6 Model 85 Stepping 7, GenuineIntel" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}