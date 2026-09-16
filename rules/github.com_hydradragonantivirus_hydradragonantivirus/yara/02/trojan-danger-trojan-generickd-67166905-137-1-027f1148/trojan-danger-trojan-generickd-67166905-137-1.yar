rule Trojan_Danger_Trojan_GenericKD_67166905_137_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_137_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29e2e5687bc274e92de1bf992b3fad0312c19df14e5ffdf8d334559f4af3394f"

  strings:
    $s1 = "^A(including the denial or cancellation of any export or other license); other event outside the reasonable control of the oblig" ascii
    $s2 = "^A(including the denial or cancellation of any export or other license); other event outside the reasonable control of the oblig" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}