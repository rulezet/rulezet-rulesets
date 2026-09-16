rule Virus_Hijack_Trojan_GenericKDZ_105930_15 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105930_15.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1150892bb4d6b0df1ae2a99d9382bf1a659486aed61cd3821496ef1c30defcf"

  strings:
    $s1 = "hOUR LICE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}