rule Trojan_Autorun_Trojan_GenericKD_72254740_11_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72254740_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "da36ac002bc36bad9f2383c6846496921d10d0361a305cd0dc3a09305d09746c"

  strings:
    $s1 = "Kor service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}