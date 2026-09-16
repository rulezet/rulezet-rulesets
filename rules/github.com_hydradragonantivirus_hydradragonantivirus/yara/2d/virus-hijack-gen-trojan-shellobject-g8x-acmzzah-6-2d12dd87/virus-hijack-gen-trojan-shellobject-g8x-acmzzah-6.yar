rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aCMzZah_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aCMzZah_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fec6690565804f5336d1071a02dde2b1f47171d097b8ec8ab2fc195afbef06a4"

  strings:
    $s1 = ":orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}