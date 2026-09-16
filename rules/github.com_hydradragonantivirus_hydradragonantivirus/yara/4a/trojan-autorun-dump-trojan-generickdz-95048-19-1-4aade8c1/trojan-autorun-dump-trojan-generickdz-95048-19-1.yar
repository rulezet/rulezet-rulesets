rule Trojan_Autorun_Dump_Trojan_GenericKDZ_95048_19_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Trojan.GenericKDZ.95048_19_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80a757c300bf33d48fbe5d9599b1442a6ca49e6ab2b7679e1b338521e6dff7d1"

  strings:
    $s1 = "8Fyour entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}