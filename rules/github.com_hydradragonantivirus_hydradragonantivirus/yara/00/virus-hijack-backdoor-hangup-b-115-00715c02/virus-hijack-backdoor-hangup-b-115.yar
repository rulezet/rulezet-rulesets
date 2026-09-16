rule Virus_Hijack_Backdoor_Hangup_B_115 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_115.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8020009014dc43c4c33085aec0f0950d0f2f67b192d805b00fa9c94d4ca34ac5"

  strings:
    $s1 = "vto be invalid or unenforceable, the remaining provisions will remain effective. It is expressly agreed that the terms of this" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}