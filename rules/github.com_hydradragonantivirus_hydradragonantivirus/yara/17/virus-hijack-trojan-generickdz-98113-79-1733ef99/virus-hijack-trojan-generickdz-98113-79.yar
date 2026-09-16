rule Virus_Hijack_Trojan_GenericKDZ_98113_79 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_79.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "790777ab5ba1e1bcdc637fd5e1a5b438340669032eabfa4d0221a1dcaa5ea54f"

  strings:
    $s1 = "+#hundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}