rule Virus_Hijack_Gen_Trojan_ShellObject_RAZ_aCEmdoo_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.RAZ@aCEmdoo_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63cb92bbe9a721fef04dc7b7ca53e8cc4f456e359a8af6ac88558de33c0692e5"

  strings:
    $s1 = "High@L" fullword ascii
    $s2 = "&:ThuS" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}