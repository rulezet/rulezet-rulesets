rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_aerna7n_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@aerna7n_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a4dc64b7df47c9397fccb7f9cf098737cfff9747a8970c039e88d226ced69bd"

  strings:
    $s1 = "local!clr-namespace:TicTacToe.GameViews" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}