rule Virus_Hijack_GenPack_Backdoor_Hangup_B_195 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_195.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6143f497169efb135c4e7f4ddf5f5d780e658dc932d07a7933d7008210069b7"

  strings:
    $s1 = "zand hardware systems to the applications programs and (c) building extensions to applications programs. You shall not" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}