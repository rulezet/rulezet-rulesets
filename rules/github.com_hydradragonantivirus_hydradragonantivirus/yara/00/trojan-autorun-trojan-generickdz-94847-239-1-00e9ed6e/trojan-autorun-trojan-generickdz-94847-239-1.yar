rule Trojan_Autorun_Trojan_GenericKDZ_94847_239_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_239_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "113bc61d190524d7d1f44a8329f6553270c73237a4f908e3855f3e7b178014a5"

  strings:
    $s1 = "?that party must agree that this agreement applies to the transfer and use of the software. You may not" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}