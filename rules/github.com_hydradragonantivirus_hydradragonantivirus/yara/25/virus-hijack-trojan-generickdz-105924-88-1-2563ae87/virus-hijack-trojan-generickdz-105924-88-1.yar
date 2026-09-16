rule Virus_Hijack_Trojan_GenericKDZ_105924_88_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_88_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "329d3e0dca27084d502232504ff322089b851e1d074dd81a105f40be8d146a36"

  strings:
    $s1 = "#POke#" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}