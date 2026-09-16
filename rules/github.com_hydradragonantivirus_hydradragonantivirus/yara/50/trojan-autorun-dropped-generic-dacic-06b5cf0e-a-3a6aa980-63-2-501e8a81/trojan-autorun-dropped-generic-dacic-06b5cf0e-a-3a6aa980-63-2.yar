rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_63_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_63_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0b8fa81bbdc0fec334afc74e0cd33f2fc941eb636cfd700129d4026a761baa4"

  strings:
    $s1 = "cOPY;K" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}