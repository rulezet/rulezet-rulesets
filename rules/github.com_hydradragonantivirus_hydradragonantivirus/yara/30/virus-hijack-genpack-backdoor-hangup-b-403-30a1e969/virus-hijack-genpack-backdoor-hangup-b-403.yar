rule Virus_Hijack_GenPack_Backdoor_Hangup_B_403 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_403.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6add7814213a4ac470af866f7c8ad19e6c6dd97527fe2ad44a7ed443cc950a13"

  strings:
    $s1 = "gcreate this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}