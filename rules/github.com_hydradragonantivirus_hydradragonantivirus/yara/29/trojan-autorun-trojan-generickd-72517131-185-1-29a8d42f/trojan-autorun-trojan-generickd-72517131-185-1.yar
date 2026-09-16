rule Trojan_Autorun_Trojan_GenericKD_72517131_185_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_185_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aab62d6bca5bd99a23f9160ef5ca2164814bc452582d4f6a1097e8d03fc72cb6"

  strings:
    $s1 = "!User, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}