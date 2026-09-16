rule Virus_Hijack_GenPack_Backdoor_Hangup_B_310 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_310.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49818cd3f990d23654d33b595c658da070be28726330aa8f42f1e83fd8b6fce8"

  strings:
    $s1 = "8the licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii
    $s2 = "lP0#!f~s%VIVA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}