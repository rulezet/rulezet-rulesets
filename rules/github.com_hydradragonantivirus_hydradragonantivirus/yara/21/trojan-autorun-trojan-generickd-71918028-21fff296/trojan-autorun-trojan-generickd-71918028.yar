rule Trojan_Autorun_Trojan_GenericKD_71918028 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.71918028.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86aff666287d597af14ae4cfb8c29d463d0de70306dcf62fcb60500e5884fe88"

  strings:
    $s1 = "b>]DArg" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}