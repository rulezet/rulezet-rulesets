rule Virus_Hijack_Backdoor_Hangup_B_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "45593633afdaf81b77048580166472c5594643276ebe991f342f9449cda94503"

  strings:
    $s1 = " edition software may not be used for commercial, non-profit, o" fullword ascii
    $s2 = "xes and expenses. You agree that you have not relied on" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}