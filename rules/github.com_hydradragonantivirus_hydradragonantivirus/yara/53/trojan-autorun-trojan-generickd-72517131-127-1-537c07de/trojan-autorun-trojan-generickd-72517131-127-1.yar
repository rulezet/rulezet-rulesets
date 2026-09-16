rule Trojan_Autorun_Trojan_GenericKD_72517131_127_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_127_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "128023d2ad12399185a29fa7a4790aa8e68988623fd68a960d0824dacc7d30a0"

  strings:
    $s1 = "LXUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}