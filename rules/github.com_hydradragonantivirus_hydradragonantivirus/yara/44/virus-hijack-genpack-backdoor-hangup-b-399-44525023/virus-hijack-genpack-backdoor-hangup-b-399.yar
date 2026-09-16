rule Virus_Hijack_GenPack_Backdoor_Hangup_B_399 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_399.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63e6177c61dacc026a894490a50bc2ff94cb7ed06320c4761247928f295f3d96"

  strings:
    $s1 = "v|the licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}