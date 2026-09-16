rule Virus_Hijack_Trojan_GenericKDZ_79663_105_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_105_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a18196d3f4625f3c214ab9a09fad844431e9255d5ed053b573babd5061d73c2"

  strings:
    $s1 = "N;gelT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}