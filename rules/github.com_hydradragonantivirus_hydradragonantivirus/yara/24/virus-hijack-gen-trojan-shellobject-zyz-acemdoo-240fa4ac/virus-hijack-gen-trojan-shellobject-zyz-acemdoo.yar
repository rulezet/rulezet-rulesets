rule Virus_Hijack_Gen_Trojan_ShellObject_zyZ_aCEmdoo {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.zyZ@aCEmdoo.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a26e4fc9926ac7930ab1451a78d345b6367b741fd147e448e662c10aac12492b"

  strings:
    $s1 = "Burg#U" fullword ascii
    $s2 = "Burg#A" fullword ascii
    $s3 = "Burg#m" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}