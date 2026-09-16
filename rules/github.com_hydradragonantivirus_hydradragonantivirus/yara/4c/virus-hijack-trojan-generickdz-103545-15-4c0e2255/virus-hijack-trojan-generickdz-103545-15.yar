rule Virus_Hijack_Trojan_GenericKDZ_103545_15 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_15.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30a5327f7efd2bfc38e277b3942d6d44cb27efeb25a79c641bbdfe2b3e9cf18e"

  strings:
    $s1 = "rsoftware features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}