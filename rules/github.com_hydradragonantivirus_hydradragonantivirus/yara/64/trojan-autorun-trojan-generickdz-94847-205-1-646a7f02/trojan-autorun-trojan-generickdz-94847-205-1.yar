rule Trojan_Autorun_Trojan_GenericKDZ_94847_205_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_205_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6695aedf272e71e2bb108fc43b34d9cae13aea5db71c9695c2121519fe627dbf"

  strings:
    $s1 = "2America, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}