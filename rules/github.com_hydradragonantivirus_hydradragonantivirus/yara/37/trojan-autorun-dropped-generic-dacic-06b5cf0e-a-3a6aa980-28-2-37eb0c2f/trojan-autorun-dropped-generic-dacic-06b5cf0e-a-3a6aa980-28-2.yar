rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_28_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_28_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2e952e672429d1d821d78168127f208e6d5821153b5be9dc600f5b82bbfad67"

  strings:
    $s1 = "}C(DILo" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}