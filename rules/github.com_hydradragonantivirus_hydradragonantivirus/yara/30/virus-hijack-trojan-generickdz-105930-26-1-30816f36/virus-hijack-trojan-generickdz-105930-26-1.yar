rule Virus_Hijack_Trojan_GenericKDZ_105930_26_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105930_26_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d1bcbf6cc72dc412a9539015e280232459e1ecd63e2fa12d00cd8b9de649114"

  strings:
    $s1 = "MOPe[pX!)" fullword ascii
    $s2 = "roLE#{+" fullword ascii
    $s3 = "y,CoRA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}