rule Virus_Hijack_GenPack_Backdoor_Hangup_B_471 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_471.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9eb810e1d14407051dea41cfd44f716823755c29ceb5120c22190c7008cafd1b"

  strings:
    $s1 = ":;of the software and a separate license for each copy. Content protected by digital rights management" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}