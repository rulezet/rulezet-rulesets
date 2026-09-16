rule Trojan_Autorun_Trojan_GenericKDZ_94847_75_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_75_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab488e2f7a4523588dad7ca663941f0160eca551e1674afcd10fcc4bef9c62f7"

  strings:
    $s1 = "Bwhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}