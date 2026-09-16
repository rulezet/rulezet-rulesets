rule Trojan_Autorun_Trojan_GenericKD_72517131_148_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_148_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3794f283c51249e3c85a0c439e616d479a6840526468e104b8770f8e786765e5"

  strings:
    $s1 = "Passets, owned or managed for others, which were " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}