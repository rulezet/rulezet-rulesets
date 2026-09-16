rule Virus_Hijack_Trojan_GenericKDZ_103285_526 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_526.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f46172dc232112df0e91751f98e9cf7c5156db01a90c3008043709e036f9b7cf"

  strings:
    $s1 = "(policy, which might require you to return the software with the entire computer on which the software is" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}