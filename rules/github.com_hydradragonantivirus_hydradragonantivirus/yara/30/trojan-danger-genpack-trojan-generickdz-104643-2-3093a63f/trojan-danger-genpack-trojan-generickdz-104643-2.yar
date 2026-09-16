rule Trojan_Danger_GenPack_Trojan_GenericKDZ_104643_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_GenPack.Trojan.GenericKDZ.104643_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1df3f51ffe481c5245c46ece088a0a6b9a4941fa5ee6d2b5c729eac3ca7271b9"

  strings:
    $s1 = "gram Files\\(7" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}