rule Virus_Hijack_Trojan_Agent_DQQO_141_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_141_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22f525a21e4148378eeae7d178a75dfc9041aabad015a35dea6878eaf05b8ce3"

  strings:
    $s1 = "p[must be " fullword ascii
    $s2 = "INTERN:" fullword ascii
    $s3 = "h(MARL" fullword ascii
    $s4 = "[>Module?" fullword ascii
    $s5 = "Next?6-" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}