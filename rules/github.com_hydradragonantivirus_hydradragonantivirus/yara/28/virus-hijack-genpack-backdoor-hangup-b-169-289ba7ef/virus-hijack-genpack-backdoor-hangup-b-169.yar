rule Virus_Hijack_GenPack_Backdoor_Hangup_B_169 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_169.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06187d99b4b7b4bd045adf54a5c65a2a6c33370fde73490c130d1577c45db560"

  strings:
    $s1 = "rthe licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}