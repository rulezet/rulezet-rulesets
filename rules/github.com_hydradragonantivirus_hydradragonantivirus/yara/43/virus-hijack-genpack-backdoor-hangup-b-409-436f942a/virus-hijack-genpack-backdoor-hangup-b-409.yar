rule Virus_Hijack_GenPack_Backdoor_Hangup_B_409 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_409.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "41fbf57501e7fe30bea154c21d6098a05c2ed64f014fc5984b2fd8d7d5968c1e"

  strings:
    $s1 = "Hcreate this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}