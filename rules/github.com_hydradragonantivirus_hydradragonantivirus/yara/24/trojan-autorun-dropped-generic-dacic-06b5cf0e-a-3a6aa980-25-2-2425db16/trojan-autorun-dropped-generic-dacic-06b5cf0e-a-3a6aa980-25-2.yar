rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_25_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_25_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "789215f22225f633317fd7195d4abdea03e23e07296ce1573218b4e0988e68db"

  strings:
    $s1 = "m(ivIn?L" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}