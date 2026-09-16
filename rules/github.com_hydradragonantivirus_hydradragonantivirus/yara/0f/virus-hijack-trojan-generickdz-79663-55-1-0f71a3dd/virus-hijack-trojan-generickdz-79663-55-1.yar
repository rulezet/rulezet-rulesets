rule Virus_Hijack_Trojan_GenericKDZ_79663_55_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_55_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "190c6e2f9ffd9a58c8ac203f218605bbe279b5a700a94b97cdeca4f21beb6473"

  strings:
    $s1 = "MeSH{w" fullword ascii
    $s2 = "aLga[$" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}