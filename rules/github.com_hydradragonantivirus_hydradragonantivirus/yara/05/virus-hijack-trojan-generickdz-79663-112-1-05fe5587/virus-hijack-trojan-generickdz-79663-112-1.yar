rule Virus_Hijack_Trojan_GenericKDZ_79663_112_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_112_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce0dc8aa9708a213bd6666868e602a7144100784ec25afd85c42707e9f461015"

  strings:
    $s1 = "TYpO<9t" fullword ascii
    $s2 = "FeAL@j" fullword ascii
    $s3 = "aXon@o" fullword ascii
    $s4 = "n=[SleW(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}