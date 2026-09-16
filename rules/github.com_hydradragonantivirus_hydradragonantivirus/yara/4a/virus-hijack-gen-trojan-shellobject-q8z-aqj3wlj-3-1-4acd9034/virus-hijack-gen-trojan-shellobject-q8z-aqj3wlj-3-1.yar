rule Virus_Hijack_Gen_Trojan_ShellObject_q8Z_aqj3wLj_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aqj3wLj_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21c734a94c730b1767635269b73e7ad8b81e6e733fa6b05fff5837b30e8ff84b"

  strings:
    $s1 = "t;geLl" fullword ascii
    $s2 = "ManT:G" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}