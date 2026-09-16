rule Virus_Hijack_GenPack_Backdoor_Hangup_B_431 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_431.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43a9f6698631c955a2ad82500ad9d7d38dd07d7d92fd4dc8af40a47012cb4ff4"

  strings:
    $s1 = "M'your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}