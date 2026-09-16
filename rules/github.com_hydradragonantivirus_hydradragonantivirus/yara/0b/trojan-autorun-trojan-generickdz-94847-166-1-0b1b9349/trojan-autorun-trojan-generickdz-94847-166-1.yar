rule Trojan_Autorun_Trojan_GenericKDZ_94847_166_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_166_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "343533b2100d31cffc22bac34896686b480a551c027e8572d1d371922afff1d8"

  strings:
    $s1 = "\\'you received the software, and also any Microsoft updates, supplements, and services for the software," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}