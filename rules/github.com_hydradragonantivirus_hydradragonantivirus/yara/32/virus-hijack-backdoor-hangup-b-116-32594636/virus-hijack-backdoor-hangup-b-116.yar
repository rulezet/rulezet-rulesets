rule Virus_Hijack_Backdoor_Hangup_B_116 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_116.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72ab42ddd8f235a3311c0204adf83dc544a64c2155e32e4c7f28fb0f6e8746be"

  strings:
    $s1 = "Acreate this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}