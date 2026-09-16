rule Virus_Infector_Gen_Trojan_ShellIni__mtaa8u9fDgi {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Gen.Trojan.ShellIni.@mtaa8u9fDgi.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38d9ec55c865ca6e62a166e73c29cc30d69a0c6e0fee8a4bea9cfe9f2d167b1b"

  strings:
    $s1 = "KXw]rifT" fullword ascii
    $s2 = "lumP<_" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}