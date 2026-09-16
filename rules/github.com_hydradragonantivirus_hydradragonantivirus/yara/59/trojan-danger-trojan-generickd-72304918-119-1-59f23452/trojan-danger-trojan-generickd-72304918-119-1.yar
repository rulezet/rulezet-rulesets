rule Trojan_Danger_Trojan_GenericKD_72304918_119_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_119_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47f0835e73d867d99cb9841e4104aab17cfc50ea3733be5cbb05ca33f1c9ee49"

  strings:
    $s1 = "UUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}