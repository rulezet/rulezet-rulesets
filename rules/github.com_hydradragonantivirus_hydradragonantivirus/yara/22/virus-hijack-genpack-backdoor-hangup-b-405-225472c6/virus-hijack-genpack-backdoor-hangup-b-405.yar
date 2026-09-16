rule Virus_Hijack_GenPack_Backdoor_Hangup_B_405 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_405.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2837d7596ba2f67c3b431402798f17cb93080f1c0bd21c281251ea69b71ffa66"

  strings:
    $s1 = "0your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}