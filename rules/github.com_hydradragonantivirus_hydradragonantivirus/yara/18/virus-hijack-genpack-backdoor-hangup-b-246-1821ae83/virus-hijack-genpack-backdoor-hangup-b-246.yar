rule Virus_Hijack_GenPack_Backdoor_Hangup_B_246 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_246.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6bbb6796d18f73b6b5fe09368ec75737a004f289cc2d406fad63b88bbefffb24"

  strings:
    $s1 = "=the licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}