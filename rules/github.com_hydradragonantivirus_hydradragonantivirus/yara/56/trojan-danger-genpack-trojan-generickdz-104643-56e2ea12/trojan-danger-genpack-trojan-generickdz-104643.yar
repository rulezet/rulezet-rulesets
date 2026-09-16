rule Trojan_Danger_GenPack_Trojan_GenericKDZ_104643 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_GenPack.Trojan.GenericKDZ.104643.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9eb84706e1d35706a1078006fcbb6778cdfd29cb68f403f474dcb02069b94d9c"

  strings:
    $s1 = "gram Files\\(7" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}