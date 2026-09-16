rule Virus_Hijack_Gen_Trojan_ShellObject_gWX_aeFgVVo_31 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gWX@aeFgVVo_31.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1cf9e4cb6ae5395a68af0d1a5fd2dab71de65be0cfe548c02e023686010c7234"

  strings:
    $s1 = "`shall be counted." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}