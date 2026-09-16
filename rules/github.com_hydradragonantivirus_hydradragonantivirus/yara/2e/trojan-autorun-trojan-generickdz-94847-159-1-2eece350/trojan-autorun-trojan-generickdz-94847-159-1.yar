rule Trojan_Autorun_Trojan_GenericKDZ_94847_159_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_159_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78e6bad48001a5a2f8b5104bf7660765a33cfa31187537b9f7b50cb5f0878884"

  strings:
    $s1 = "]America, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}