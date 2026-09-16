rule Trojan_Danger_Dropped_Generic_Dacic_1A48D031_A_67758991_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Dropped.Generic.Dacic.1A48D031.A.67758991_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d689f82a8c01fa71252bc079d10d8239df1f546af84420ac65467b62b3d21aeb"

  strings:
    $s1 = "PROCESSOR_IDENTIFIER=Intel64 Family 6 Model 85 Stepping 7, GenuineIntel" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}