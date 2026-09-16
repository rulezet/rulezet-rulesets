rule Virus_Hijack_Trojan_GenericKDZ_98113_300 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_300.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95ba1b0b4ce77116dd84b719a0b0598a16b6d0da7c8152aaa2d4ed18d5356df6"

  strings:
    $s1 = "$6hundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}