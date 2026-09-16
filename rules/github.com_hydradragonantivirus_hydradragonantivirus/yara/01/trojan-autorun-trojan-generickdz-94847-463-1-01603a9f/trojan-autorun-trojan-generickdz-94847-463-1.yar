rule Trojan_Autorun_Trojan_GenericKDZ_94847_463_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_463_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d44dfe7a8aae9c594742259756feb2d50a8db69ed20b8f1e8ad981f0dc0104df"

  strings:
    $s1 = "Qorders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}