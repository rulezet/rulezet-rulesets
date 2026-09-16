rule Virus_Hijack_GenPack_Backdoor_Hangup_B_445 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_445.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6cefd39cacc2d07b2081aaba347ea0daccafc9ec679f8bea75ced9b76c6a23db"

  strings:
    $s1 = "N%your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}