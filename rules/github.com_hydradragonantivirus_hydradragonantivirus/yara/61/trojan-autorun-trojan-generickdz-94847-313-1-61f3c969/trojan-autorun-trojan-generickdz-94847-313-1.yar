rule Trojan_Autorun_Trojan_GenericKDZ_94847_313_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_313_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a38725769d567ac4ed0f5c6019ff68d0b73a43265f671d1f3f7e5b0c202ab707"

  strings:
    $s1 = "PsAmerica, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}