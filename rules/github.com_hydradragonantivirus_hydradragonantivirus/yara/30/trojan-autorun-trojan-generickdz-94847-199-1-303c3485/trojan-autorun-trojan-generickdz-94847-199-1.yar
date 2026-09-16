rule Trojan_Autorun_Trojan_GenericKDZ_94847_199_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_199_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37dbe38ded2017f7a01560b1c0055fedf9a35767cbfc71eae115488fd069d1ed"

  strings:
    $s1 = "zyou received the software, and also any Microsoft updates, supplements, and services for the software," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}