rule Virus_Hijack_Backdoor_Hangup_B_242 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_242.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2af73e5de1ef641a46a8c102068b97d391e010cc1e21795867b811d79bb56836"

  strings:
    $s1 = "Rcreate this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}