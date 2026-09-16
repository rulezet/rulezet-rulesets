rule Virus_Hijack_Backdoor_Hangup_B_310 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_310.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b7ff4dd14c248a88d5951ccc186f3d93000c9f852b2fd5c1b8367fef54f11fb"

  strings:
    $s1 = "~create this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}