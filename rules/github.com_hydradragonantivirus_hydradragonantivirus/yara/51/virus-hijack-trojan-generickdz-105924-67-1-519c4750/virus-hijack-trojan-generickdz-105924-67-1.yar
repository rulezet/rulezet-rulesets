rule Virus_Hijack_Trojan_GenericKDZ_105924_67_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_67_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1796d3e7839f9bd7515c6003bc2463308404947456aeed9cf252e5a883f50ac"

  strings:
    $s1 = "iLkA?a" fullword ascii
    $s2 = "waNe`:" fullword ascii
    $s3 = ":Edit@" fullword ascii
    $s4 = "STIR)R" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}