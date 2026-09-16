rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_79_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_79_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84d545b1ad6dc4644b7a7351e0eec653309c72b4b70e7b1a102652b78d5717f4"

  strings:
    $s1 = ",PLEx*" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}