rule Virus_Hijack_GenPack_Backdoor_Hangup_B_303 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_303.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6293224abfb8e0bb43799014d2f1aa7034dc59cfa5342210fb033e73b19f6af2"

  strings:
    $s1 = "#your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}