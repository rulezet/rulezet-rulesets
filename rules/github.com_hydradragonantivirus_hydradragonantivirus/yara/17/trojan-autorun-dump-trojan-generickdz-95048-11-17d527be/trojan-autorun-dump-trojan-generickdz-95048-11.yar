rule Trojan_Autorun_Dump_Trojan_GenericKDZ_95048_11 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Trojan.GenericKDZ.95048_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ef3ac3eab02a77b3eada99d3f0bd971a20dfebf57a583412f6883a575be8801"

  strings:
    $s1 = "613;gj>8>9;CorF@FACKwzNHNIKS" fullword ascii
    $s2 = "f`fack" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}