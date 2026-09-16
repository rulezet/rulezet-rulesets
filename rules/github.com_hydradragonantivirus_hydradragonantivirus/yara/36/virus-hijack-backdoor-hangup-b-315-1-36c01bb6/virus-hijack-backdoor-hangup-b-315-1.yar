rule Virus_Hijack_Backdoor_Hangup_B_315_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_315_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff79cbd618fcb82e3a6797f23923989834f952323427fa70c1fa2a6d0476ca09"

  strings:
    $s1 = "services. We may also share it with others, such as hardware and software" fullword ascii
    $s2 = "s fees. You and Microsoft agree to the terms governing procedures, f" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}