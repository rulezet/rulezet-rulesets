rule Virus_Hijack_Trojan_GenericKDZ_98113_169 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_169.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df1feae454dd8c702559996abb7108cf2db3505648f88c030b7e62dd63ee9be2"

  strings:
    $s1 = "vhundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}