rule Virus_Hijack_Trojan_GenericKDZ_103285_259 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_259.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "62c6a88256ed18eb329dc73cbcf0a625ae204cd4a50698fc597ca3a372355d4b"

  strings:
    $s1 = "DXvirtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}