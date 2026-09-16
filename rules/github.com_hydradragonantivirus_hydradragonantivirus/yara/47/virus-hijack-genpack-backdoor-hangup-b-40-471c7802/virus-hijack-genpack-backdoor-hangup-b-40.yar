rule Virus_Hijack_GenPack_Backdoor_Hangup_B_40 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_40.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "062431d27220bc1dec310f90fc6e846d32cdbf03836f4b7191ccaf9495befdd7"

  strings:
    $s1 = "F<create this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}