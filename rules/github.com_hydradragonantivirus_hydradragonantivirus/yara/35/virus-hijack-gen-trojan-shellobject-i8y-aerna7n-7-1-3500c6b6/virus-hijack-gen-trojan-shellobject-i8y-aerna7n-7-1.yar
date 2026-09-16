rule Virus_Hijack_Gen_Trojan_ShellObject_i8Y_aerna7n_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Y@aerna7n_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8dc1640499a6b1cac921adb0e5899e2fe02f4902b2f6acfa5d4f7c2f277e54cc"

  strings:
    $s1 = "local!clr-namespace:TicTacToe.GameViews" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}