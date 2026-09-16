rule Trojan_Autorun_Trojan_GenericKDZ_94847_263_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_263_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf511176a08b0c120f4677e0f077b3797d9250c75555a5fc47fd5769346e23fe"

  strings:
    $s1 = "horders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}