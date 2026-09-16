rule Trojan_Autorun_Trojan_GenericKD_72517131_162_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_162_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c58f3ff06ebba0731253436d1549920edcfcf32c323c0fcc41ddc3256f1541f3"

  strings:
    $s1 = "`functionality of the programs. You have 30 days " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}