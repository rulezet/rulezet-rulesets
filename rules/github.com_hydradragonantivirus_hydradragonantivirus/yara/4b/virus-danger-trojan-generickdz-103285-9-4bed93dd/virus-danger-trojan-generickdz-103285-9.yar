rule Virus_Danger_Trojan_GenericKDZ_103285_9 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Trojan.GenericKDZ.103285_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e29ff182a242740740c8f641cdcb442ddc26cdd6ad51f93033a369bd9d6b02a"

  strings:
    $s1 = "$policy, which might require you to return the software with the entire computer on which the software is" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}