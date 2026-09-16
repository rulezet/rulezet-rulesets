rule Virus_Hijack_Backdoor_Hangup_B_85 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_85.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f39ae21879d8d46632fd0d38c3efdd824008131b7f003d56065e0e5c957ecaa"

  strings:
    $s1 = "|your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}