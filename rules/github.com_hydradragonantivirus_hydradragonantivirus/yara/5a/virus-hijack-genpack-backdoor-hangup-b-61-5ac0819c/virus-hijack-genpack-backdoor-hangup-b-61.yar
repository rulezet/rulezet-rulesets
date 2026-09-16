rule Virus_Hijack_GenPack_Backdoor_Hangup_B_61 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_61.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5bd3a0b7c7560a4e836a05abf4058007cfc4ed2435340171b5eb028ee437a61"

  strings:
    $s1 = "@2A. Agreement Definitions" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}