rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_a0DbbBi_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c75b03c388cfb56a689bf94d4cfcb3d8048d8270e82901f9b533c12567015935"

  strings:
    $s1 = "access to the Oracle iSupport program may not be licensed as Employee Users, but must be licensed as `" fullword ascii
    $s2 = "aOdispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}