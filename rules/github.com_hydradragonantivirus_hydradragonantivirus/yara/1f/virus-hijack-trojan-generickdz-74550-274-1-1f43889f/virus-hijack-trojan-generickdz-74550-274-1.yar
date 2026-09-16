rule Virus_Hijack_Trojan_GenericKDZ_74550_274_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_274_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1eb6c8e64355bff865b885617b96664139a3b49b14b3e4adda449505e0476513"

  strings:
    $s1 = "&>Vila" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}