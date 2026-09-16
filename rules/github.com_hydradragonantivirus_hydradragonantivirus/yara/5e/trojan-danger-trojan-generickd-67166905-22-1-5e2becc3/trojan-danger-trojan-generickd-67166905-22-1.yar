rule Trojan_Danger_Trojan_GenericKD_67166905_22_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_22_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "529bc4d155cf3cbceba6432598275e3ebc3b948c80d7b666893395ed36f7f49c"

  strings:
    $s1 = "4purposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}