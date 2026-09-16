rule Trojan_Autorun_Trojan_GenericKDZ_95048_25_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.95048_25_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c39755f9d5bd4ffac586223d22dfae9651cfeaee657ea9d1a6dfd7218970e499"

  strings:
    $s1 = "%9orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}