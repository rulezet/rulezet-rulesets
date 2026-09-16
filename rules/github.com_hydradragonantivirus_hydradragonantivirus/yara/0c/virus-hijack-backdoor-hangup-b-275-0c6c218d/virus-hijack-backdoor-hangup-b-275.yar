rule Virus_Hijack_Backdoor_Hangup_B_275 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_275.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb82b0bf86c8aadd1e660368f3ea1321b83e50b6165820cda7ff3c47793944c1"

  strings:
    $s1 = "?`your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}