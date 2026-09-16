rule Trojan_Autorun_Trojan_GenericKDZ_94847_308_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_308_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e42ee93f04c9fd9daca7ce4c43e073ca48a858e2830bcc3d5f3f3ab22379133"

  strings:
    $s1 = "a[that party must agree that this agreement applies to the transfer and use of the software. You may not" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}