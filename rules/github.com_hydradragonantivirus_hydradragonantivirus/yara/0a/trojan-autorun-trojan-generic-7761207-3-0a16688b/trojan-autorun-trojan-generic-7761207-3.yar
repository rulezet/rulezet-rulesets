rule Trojan_Autorun_Trojan_Generic_7761207_3 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.Generic.7761207_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb604cb6e20f678411bd22208f584eabb35455f1b70f67d2aa1d899ffbe409fe"

  strings:
    $s1 = "BlaH@4" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}