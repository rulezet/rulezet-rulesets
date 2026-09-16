rule Virus_Hijack_Backdoor_Hangup_B_110 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_110.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46bcc69f60a923f4588773cd80c7658d167613f8e07b5a3e4071ed963355323b"

  strings:
    $s1 = ",the licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}