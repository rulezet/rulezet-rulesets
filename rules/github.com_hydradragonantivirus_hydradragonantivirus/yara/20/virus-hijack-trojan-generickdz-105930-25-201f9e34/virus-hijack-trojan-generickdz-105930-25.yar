rule Virus_Hijack_Trojan_GenericKDZ_105930_25 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105930_25.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72c2518e0dc181bc0ac7061d914f580646808ad9471242e348bc16595ded1ff7"

  strings:
    $s1 = "sOUR LICE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}