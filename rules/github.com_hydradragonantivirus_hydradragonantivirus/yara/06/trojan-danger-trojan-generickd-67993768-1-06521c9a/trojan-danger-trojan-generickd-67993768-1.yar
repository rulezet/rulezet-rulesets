rule Trojan_Danger_Trojan_GenericKD_67993768_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67993768_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0902a36a3eeca35ea8e3d424d54af350f22820fe2a4e46a654a8b85c414a6d3"

  strings:
    $s1 = "TRap?<RRRRRRRRRRRRRRRRRRRRn" fullword ascii
    $s2 = "TRap?<RRRRRRRRRRRRRRRRRRna" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}