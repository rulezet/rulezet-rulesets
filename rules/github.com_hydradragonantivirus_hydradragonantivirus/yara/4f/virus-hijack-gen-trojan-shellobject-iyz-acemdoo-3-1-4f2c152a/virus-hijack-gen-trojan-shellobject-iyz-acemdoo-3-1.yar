rule Virus_Hijack_Gen_Trojan_ShellObject_IyZ_aCEmdoo_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.IyZ@aCEmdoo_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12336d87474939b20c1c94a5f6ed0804690019f8a54ed82b85435eea27b4580c"

  strings:
    $s1 = "GUGU?@" fullword ascii
    $s2 = "wOKe[2" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}