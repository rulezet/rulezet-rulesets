rule Virus_Hijack_Trojan_GenericKDZ_98113_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3069329b41c1a0646b5f36ab570582d6ad33e3abdc39f43c681a5df8dbfbd852"

  strings:
    $s1 = "Riff<4" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}