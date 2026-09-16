rule Virus_Hijack_Backdoor_Hangup_B_83 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_83.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bef2749886f69998ef0574e957b48e36bd4a6f86e8cf388038bf0107e5a746a8"

  strings:
    $s1 = "ecreate this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}