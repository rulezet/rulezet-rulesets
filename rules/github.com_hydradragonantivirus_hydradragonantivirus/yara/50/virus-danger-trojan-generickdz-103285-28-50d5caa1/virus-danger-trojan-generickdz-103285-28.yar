rule Virus_Danger_Trojan_GenericKDZ_103285_28 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Trojan.GenericKDZ.103285_28.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "814179c6bb73abea80c4ca97cd2936add4fe768855feed4936f8899bc6fa316d"

  strings:
    $s1 = "If you choose not to renew the membership, all rights to use the Pre`" fullword ascii
    $s2 = "Ca neutral arbitrator, whose decision will be final except for a limited right of appeal under the Federal" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}