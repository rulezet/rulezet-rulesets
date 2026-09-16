rule Virus_Hijack_GenPack_Backdoor_Hangup_B_291 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_291.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a3b9b345b0e1ea1505e7187a18120887bd6d26ead51945b93c653980188c6d1"

  strings:
    $s1 = ";create this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}