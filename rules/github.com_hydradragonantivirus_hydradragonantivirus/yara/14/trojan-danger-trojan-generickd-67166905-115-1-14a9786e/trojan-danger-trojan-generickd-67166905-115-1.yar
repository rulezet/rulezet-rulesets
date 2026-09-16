rule Trojan_Danger_Trojan_GenericKD_67166905_115_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_115_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16106eefad279474b11f48d7912ac924a5b0b417ed0de10a2c25962f6ab472ed"

  strings:
    $s1 = "JITi?;UyW!" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}