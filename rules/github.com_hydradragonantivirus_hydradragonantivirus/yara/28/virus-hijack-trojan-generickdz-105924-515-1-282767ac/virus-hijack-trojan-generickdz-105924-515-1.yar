rule Virus_Hijack_Trojan_GenericKDZ_105924_515_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_515_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "317101aa73f400cee6b22e099bc8803e8b1128de62dc31e7e7b038b8cb2dbf43"

  strings:
    $s1 = "]WHUP%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}