rule Trojan_Autorun_Trojan_GenericKDZ_95768 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.95768.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5620fcc088421f808afc8790062077f49cbe416d0da2a4d65c0e7a0d8af03a29"

  strings:
    $s1 = "SUsu})" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}