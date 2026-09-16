rule Trojan_Danger_Trojan_GenericKD_67166905_452_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_452_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f86a7fc26ca527ae75450e347489071cf51f5f0e870e234c20eea3dbfe19bcd9"

  strings:
    $s1 = "+virtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}