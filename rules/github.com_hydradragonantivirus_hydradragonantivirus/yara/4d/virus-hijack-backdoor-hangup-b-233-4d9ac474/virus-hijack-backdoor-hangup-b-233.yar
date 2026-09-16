rule Virus_Hijack_Backdoor_Hangup_B_233 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_233.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ece03a34f83a0abf6a7f438f2b5e1c7c4f24b469b0a224b301a5d3bc15918bd"

  strings:
    $s1 = "gcreate this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}