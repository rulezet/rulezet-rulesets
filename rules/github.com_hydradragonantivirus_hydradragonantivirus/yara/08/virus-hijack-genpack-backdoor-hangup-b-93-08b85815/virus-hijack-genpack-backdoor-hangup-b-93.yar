rule Virus_Hijack_GenPack_Backdoor_Hangup_B_93 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_93.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa0f685ee252220dc3e45c3b4c3cbf104df91fb06a0cb249d6415ae8265e6f23"

  strings:
    $s1 = "<create this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}