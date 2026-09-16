rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_ae3yXvm_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "706965368357ae1729f13d9032c5ba84511c3104b723e685d9358af6472981e0"

  strings:
    $s1 = "Darkick Commander" fullword ascii
    $s2 = "Font(TD" fullword ascii
    $s3 = "Color`ND" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}