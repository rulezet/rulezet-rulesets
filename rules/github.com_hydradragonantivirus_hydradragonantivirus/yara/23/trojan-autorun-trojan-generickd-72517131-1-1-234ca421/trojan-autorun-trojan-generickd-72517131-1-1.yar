rule Trojan_Autorun_Trojan_GenericKD_72517131_1_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1dbf383c02655a4a89a387d30d9d9ff8f69fd5e6c085b2032eaa737f1d94b7d6"

  strings:
    $s1 = "skAt!mR5" fullword ascii
    $s2 = "skAt!]j6" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}