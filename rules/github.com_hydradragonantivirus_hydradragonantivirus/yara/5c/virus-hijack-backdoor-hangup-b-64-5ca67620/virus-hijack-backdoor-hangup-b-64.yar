rule Virus_Hijack_Backdoor_Hangup_B_64 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_64.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "369b780217a87fb2220a6e0278da0b5de38c644ae266f52a1338231f02dd619d"

  strings:
    $s1 = "_9Trade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data, information," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}