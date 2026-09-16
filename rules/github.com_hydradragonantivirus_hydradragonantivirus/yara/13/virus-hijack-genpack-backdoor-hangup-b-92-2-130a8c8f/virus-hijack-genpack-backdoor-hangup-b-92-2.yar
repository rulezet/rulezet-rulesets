rule Virus_Hijack_GenPack_Backdoor_Hangup_B_92_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_92_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06ee0a3c25a6c643ac4a2c0075b12f3dc2e76d454ac68549631eb5dd967450d2"

  strings:
    $s1 = "sesS,\\`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}