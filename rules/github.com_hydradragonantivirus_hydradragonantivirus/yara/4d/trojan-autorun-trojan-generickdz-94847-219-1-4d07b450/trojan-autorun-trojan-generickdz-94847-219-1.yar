rule Trojan_Autorun_Trojan_GenericKDZ_94847_219_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_219_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e0c8b6b7bae05e51a9529339dc9b9513283ad4ce14278240cea4bbc459bf157"

  strings:
    $s1 = "breaching party continues reasonable efforts to cure the breach. You agree that if you " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}