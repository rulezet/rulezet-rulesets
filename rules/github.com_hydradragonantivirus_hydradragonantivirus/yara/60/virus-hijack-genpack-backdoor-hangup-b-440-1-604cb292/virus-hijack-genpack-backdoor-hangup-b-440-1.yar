rule Virus_Hijack_GenPack_Backdoor_Hangup_B_440_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_440_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2fee96d83cd53b2b346ba7e72285d511de0fb3419e8f54da80fc9034a7929ac1"

  strings:
    $s1 = ",Reference Viewing Co" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}