rule Virus_Hijack_GenPack_Backdoor_Hangup_B_111 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_111.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c42a15eb4402f6337c8c0f4fb9941267b6638f979c7c633c10e7ca2cd97f3044"

  strings:
    $s1 = "wothe licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}