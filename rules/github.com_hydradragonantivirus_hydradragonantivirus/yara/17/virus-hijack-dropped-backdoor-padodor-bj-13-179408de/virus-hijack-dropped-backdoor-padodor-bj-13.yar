rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_13 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "947c5f640706757300d948eb1a7032b051dc284a21d1af5a143744d2029bb73c"

  strings:
    $s1 = "If you want to find out more about academic soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}