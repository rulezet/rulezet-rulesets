rule Virus_Hijack_Trojan_GenericKDZ_103545_43 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_43.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a091ee17ddb4cf890794426634f291b887370fd9c0e8dd46b551371147af0dd6"

  strings:
    $s1 = "Q)software features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}