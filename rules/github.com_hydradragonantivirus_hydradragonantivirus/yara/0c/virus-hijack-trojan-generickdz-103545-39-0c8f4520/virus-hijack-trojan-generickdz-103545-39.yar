rule Virus_Hijack_Trojan_GenericKDZ_103545_39 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_39.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7733858a2749251c4c8368bbb49c86c87f45158c15463830bb6e931db33a418"

  strings:
    $s1 = "}software features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}