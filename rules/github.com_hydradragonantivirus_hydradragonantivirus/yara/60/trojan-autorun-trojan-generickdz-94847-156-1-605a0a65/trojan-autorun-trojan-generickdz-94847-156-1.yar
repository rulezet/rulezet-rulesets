rule Trojan_Autorun_Trojan_GenericKDZ_94847_156_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_156_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e22b928a0185afb99d74702ed755f90dc79096609417678e69ab15ca3ff2f44c"

  strings:
    $s1 = "5automatically sign you into the software using the same Microsoft account. This allows you to store and" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}