rule Virus_Hijack_GenPack_Backdoor_Hangup_B_91 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_91.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3d2ccb612accf746cc6a81ee8424c4709efd77d6528c829c8959f9e6388ffe8"

  strings:
    $s1 = "MYto be invalid or unenforceable, the remaining provisions will remain effective. It is expressly agreed that the terms of this" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}