rule Virus_Hijack_Trojan_GenericKDZ_98113_372_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_372_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17ef10abc3c45d1ca38875af67c45da264f03bbf307a517c4228280a4c460b20"

  strings:
    $s1 = "@\"pUlY{^" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}