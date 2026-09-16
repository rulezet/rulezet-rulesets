rule Virus_Hijack_Trojan_GenericKDZ_98388_49_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_49_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93f26bd9774de530b7e4f1c4078c96be1789913785aa2fcde65a81bd8972165e"

  strings:
    $s1 = "TUCk;ff" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}