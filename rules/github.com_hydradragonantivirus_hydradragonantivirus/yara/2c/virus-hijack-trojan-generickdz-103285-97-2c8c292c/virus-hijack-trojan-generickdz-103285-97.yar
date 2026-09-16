rule Virus_Hijack_Trojan_GenericKDZ_103285_97 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_97.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09801c49acfc9c8787e0cd42b68d964f7c0b1921eeed17fc419c88d7b7cb9161"

  strings:
    $s1 = "la neutral arbitrator, whose decision will be final except for a limited right of appeal under the Federal" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}