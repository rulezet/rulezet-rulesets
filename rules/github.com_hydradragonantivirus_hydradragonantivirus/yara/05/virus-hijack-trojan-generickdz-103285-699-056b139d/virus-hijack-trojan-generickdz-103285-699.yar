rule Virus_Hijack_Trojan_GenericKDZ_103285_699 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_699.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d498a3a9a5ba2aa0f2634bd4f0d41471a5d334d3d501a8ed6c694a8d8bbb6efc"

  strings:
    $s1 = "8UUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}