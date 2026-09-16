rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aiZXqXc_13_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aiZXqXc_13_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1438104b9090e6cbbf83f3afa232d4a05a7ad1a9be7812f919380b51b993c94c"

  strings:
    $s1 = "Register Me.exe" fullword wide
    $s2 = "Modified by an unpaid evaluation copy of Resource Tuner 2 (www.heaventools.com)" fullword wide
    $s3 = "Register Me%" fullword ascii
    $s4 = "Register Me$" fullword ascii
    $s5 = "Register Me.g.resources" fullword ascii
    $s6 = "Register Me" fullword ascii
    $s7 = "<Module>{B9E6D315-7D9A-4303-9E50-D1C5EEB1A640}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}