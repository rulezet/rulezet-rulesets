rule Virus_Hijack_Backdoor_Hangup_B_96 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_96.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e5bb56821fae395058c92359fcf7f26b88ec0ed09b6468b3a581c3faec641a6"

  strings:
    $s1 = " create this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}