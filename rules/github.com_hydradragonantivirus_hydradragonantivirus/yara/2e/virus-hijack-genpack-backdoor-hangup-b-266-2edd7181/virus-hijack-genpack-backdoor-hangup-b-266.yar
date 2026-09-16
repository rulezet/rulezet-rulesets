rule Virus_Hijack_GenPack_Backdoor_Hangup_B_266 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_266.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b61c934d601c27ff267448927380591be42dc608ac4ca40dc5d1fac75901228"

  strings:
    $s1 = "Qthe licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}