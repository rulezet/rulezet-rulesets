rule Virus_Hijack_Backdoor_Hangup_B_47_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_47_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4f22881a348604fc70000f8b655287aafa3052cc37278513a92a105d8f84b88"

  strings:
    $s1 = " license is the" fullword ascii
    $s2 = "Person: is defined as your employee or" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}