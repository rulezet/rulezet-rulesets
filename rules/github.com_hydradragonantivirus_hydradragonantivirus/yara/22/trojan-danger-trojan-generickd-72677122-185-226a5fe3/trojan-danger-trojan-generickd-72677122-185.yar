rule Trojan_Danger_Trojan_GenericKD_72677122_185 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_185.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34fefdaec5b14c0d3b2d286cc8c95e025d15c6be4a778f51bdee144dabb2d06d"

  strings:
    $s1 = "V[TRap?<RRRRRRRRRRna" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}