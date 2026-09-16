rule Virus_Hijack_Trojan_GenericKDZ_98113_319_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_319_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52bcb141f3c89870642651440b67cd2cef5f60acad4d270b7e6383704d50b2f3"

  strings:
    $s1 = "WaUP<8y`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}