rule Virus_Hijack_Trojan_GenericKDZ_105921_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105921_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cafa0f036a4a9cc4b2cd5e05689b9f4099337130c058fcdfc2e664cf8166bcb4"

  strings:
    $s1 = "#~2013 software. For your convenience, we" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}