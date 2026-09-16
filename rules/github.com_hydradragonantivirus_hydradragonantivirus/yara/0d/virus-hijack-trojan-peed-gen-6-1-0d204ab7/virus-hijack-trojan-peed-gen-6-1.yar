rule Virus_Hijack_Trojan_Peed_Gen_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Peed.Gen_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02cc5392b258109d665cdc7efff02dab8eab5de45183981580a8bc0500882584"

  strings:
    $s1 = "SHeD(I" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}