rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_32_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_32_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60ba2eb134f033ab5acf50c4ea1eea0b8329a74150ceb611c64c08550f794eee"

  strings:
    $s1 = "Darkick Commander" fullword ascii
    $s2 = "Font(TD" fullword ascii
    $s3 = "Color`ND" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}