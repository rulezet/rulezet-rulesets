rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aCMzZah_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aCMzZah_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f9d987f543cd7d3c1d09ad9aa4923467ddb071972ec26b4051c434c0c9ae8e64"

  strings:
    $s1 = "torders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}