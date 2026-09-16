rule Virus_Hijack_Trojan_GenericKDZ_79663_87_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_87_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0380f7e36689f767fa617811e844b8a10db826d3f205deac7528c8a36f125c9f"

  strings:
    $s1 = "EsNe ," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}