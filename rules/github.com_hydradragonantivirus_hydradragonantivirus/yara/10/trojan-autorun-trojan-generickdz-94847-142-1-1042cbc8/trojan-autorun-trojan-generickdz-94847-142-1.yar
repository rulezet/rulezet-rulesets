rule Trojan_Autorun_Trojan_GenericKDZ_94847_142_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_142_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76a3a6d8232a8c88f7ffa97662d97942c7ba26c2d401cebd1efd433d6649887f"

  strings:
    $s1 = "TP&OS@PuKU" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}