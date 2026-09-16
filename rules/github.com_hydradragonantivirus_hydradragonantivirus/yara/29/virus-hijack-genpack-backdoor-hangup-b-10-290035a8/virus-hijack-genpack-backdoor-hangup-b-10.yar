rule Virus_Hijack_GenPack_Backdoor_Hangup_B_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89796db6bdb7b4e4a7ed693582c119f52e41df45205e9d0346f8a42a0026677a"

  strings:
    $s1 = "`create this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}