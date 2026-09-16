rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_aCkwazk_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@aCkwazk_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24384171a00b19cabc9d68b2b82f1852453969923413d70b736df31d10cd056a"

  strings:
    $s1 = "tjxgt(plud" fullword ascii
    $s2 = "t(plud" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}