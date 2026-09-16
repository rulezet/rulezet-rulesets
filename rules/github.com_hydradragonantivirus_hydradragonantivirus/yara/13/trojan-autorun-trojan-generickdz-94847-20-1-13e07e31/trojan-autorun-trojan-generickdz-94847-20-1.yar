rule Trojan_Autorun_Trojan_GenericKDZ_94847_20_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_20_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e22bd92e549898b99865d26aa5ddf91e0f929034629206212721e5d2db9ba726"

  strings:
    $s1 = "6you received the software, and also any Microsoft updates, supplements, and services for the software," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}