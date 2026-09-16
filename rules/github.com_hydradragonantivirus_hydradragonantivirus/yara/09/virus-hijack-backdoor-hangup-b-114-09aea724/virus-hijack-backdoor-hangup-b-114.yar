rule Virus_Hijack_Backdoor_Hangup_B_114 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_114.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "083f715cf12dca7281ad188b2fb8d2dfc6fe0212d64e324146198decbf48ca2d"

  strings:
    $s1 = "nyour entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}