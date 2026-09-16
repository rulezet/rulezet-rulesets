rule Virus_Hijack_GenPack_Backdoor_Hangup_B_191 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_191.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "518880d149e4f038e62462fcb3a41135dff486cc5bc23c2989abf31741afa6b7"

  strings:
    $s1 = "5your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}