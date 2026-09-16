rule Trojan_Autorun_Dump_Trojan_GenericKDZ_95048_21 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Trojan.GenericKDZ.95048_21.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70ff60433e6a506d3426e36dba0d424469c36ddfd159a9123df1a5d8fab9cdcd"

  strings:
    $s1 = "613;gj>8>9;CorF@FACKwzNHNIKS" fullword ascii
    $s2 = "f`fack" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}