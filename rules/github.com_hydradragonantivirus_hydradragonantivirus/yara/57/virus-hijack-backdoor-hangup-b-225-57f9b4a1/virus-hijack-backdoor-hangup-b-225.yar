rule Virus_Hijack_Backdoor_Hangup_B_225 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_225.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0d53ef8623570c1ddbc2beda9af8517641aaa7a4eee142538075bd9522123a2"

  strings:
    $s1 = "Tthe licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}