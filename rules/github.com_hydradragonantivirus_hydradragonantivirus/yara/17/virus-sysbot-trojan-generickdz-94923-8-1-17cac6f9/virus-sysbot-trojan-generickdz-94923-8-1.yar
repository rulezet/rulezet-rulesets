rule Virus_Sysbot_Trojan_GenericKDZ_94923_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKDZ.94923_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5532f3699b01676915cc083ea7fcc3d5bd5b1bf0299a15ea67d0970d26ba4231"

  strings:
    $s1 = "Shearwater" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}