rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_81_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_81_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "153c809830e3f3aa2b665e71f01bc167ce6a0e33734582297d62cced49e77db1"

  strings:
    $s1 = "x`SEck'G:" fullword ascii
    $s2 = "\"hALo{" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}