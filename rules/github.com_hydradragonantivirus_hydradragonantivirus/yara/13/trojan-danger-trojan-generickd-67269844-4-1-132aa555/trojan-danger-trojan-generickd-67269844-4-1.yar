rule Trojan_Danger_Trojan_GenericKD_67269844_4_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67269844_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86f555d3ce0aaafa5842f17f89c7011387821433a10f9222c5eef15d12d98b4b"

  strings:
    $s1 = "[DUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}