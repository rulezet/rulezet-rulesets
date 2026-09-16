rule Trojan_Danger_Trojan_GenericKD_67166905_388 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_388.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8f73d21bed339d01a9e38318534d38e2cb0b9e73a63730cd6a8adc36e70952c"

  strings:
    $s1 = "ODBC Data Sources (32-bit).lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}