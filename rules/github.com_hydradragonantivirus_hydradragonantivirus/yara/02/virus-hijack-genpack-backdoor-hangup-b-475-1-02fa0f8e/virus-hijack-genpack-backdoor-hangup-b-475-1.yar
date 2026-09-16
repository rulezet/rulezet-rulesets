rule Virus_Hijack_GenPack_Backdoor_Hangup_B_475_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_475_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0b77f70989ff2a984bf1289ebdc2a193f1a4fba67fd52407d8adee3e81bb4ff"

  strings:
    $s1 = "ewing Condition in IEC61966-2.1" fullword ascii
    $s2 = ",Reference V" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}