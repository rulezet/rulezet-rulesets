rule Virus_Hijack_Trojan_GenericKDZ_98388_182_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_182_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "efa7692a9aa634bba99956b4010c0bd17d52bfe428d88482361b42bd457f05f0"

  strings:
    $s1 = "WooL$I" fullword ascii
    $s2 = "lP*SLow" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}