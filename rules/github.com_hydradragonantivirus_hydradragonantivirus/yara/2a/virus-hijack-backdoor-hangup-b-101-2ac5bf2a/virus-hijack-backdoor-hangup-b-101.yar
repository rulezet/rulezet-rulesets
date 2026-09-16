rule Virus_Hijack_Backdoor_Hangup_B_101 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_101.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02ba682d69229b301fffa0fb74292f449b92567aa8e34278d741a8c150b19a90"

  strings:
    $s1 = "|your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}