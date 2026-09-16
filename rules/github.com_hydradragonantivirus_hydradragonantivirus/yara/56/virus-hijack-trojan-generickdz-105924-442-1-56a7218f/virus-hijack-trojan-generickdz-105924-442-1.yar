rule Virus_Hijack_Trojan_GenericKDZ_105924_442_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_442_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58d9620484e66288726613ccffbe4115e41164f822ad58f124d995b65e365179"

  strings:
    $s1 = "g(hurl" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}