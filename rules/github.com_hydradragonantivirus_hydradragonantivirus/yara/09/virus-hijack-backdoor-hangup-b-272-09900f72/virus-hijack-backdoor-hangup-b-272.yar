rule Virus_Hijack_Backdoor_Hangup_B_272 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_272.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "382d2ca44fc9da4415166e4328d6f5ffae76111549147e299a11ce63601d14b6"

  strings:
    $s1 = "07and hardware systems to the applications programs and (c) building extensions to applications programs. You shall not" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}