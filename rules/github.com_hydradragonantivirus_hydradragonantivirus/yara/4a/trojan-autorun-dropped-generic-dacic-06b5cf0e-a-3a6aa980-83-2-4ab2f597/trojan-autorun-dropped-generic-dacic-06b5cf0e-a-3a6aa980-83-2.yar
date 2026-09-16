rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_83_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_83_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "294e8f2c50898f335f7759515cb6956d90c67696190a8ac6552e3aa322b40de7"

  strings:
    $s1 = "H$)!InBY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}