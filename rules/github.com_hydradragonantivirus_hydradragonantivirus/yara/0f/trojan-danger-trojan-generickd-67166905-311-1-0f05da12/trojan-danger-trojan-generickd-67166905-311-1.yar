rule Trojan_Danger_Trojan_GenericKD_67166905_311_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_311_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0765328c033a2d67b211297e5aad5cd89147b428bcba0bb723c96647e7bc6984"

  strings:
    $s1 = "xpolicy, which might require you to return the software with the entire computer on which the software is" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}