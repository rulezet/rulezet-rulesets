rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_331_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_331_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43a38a960f9acd370caf87b5d32b83798336495e4f63e70f8852869a239acbff"

  strings:
    $s1 = "@pYRe@" fullword ascii
    $s2 = "@tYRe@" fullword ascii
    $s3 = "@PYRe@" fullword ascii
    $s4 = "@lYRe@" fullword ascii
    $s5 = "@LYRe@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}