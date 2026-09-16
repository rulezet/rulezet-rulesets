rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aO3zEnn_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aO3zEnn_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc4d7514ba8e969a721835de410d0746e438fd0e1aa9b9832470a1d58dfbb790"

  strings:
    $s1 = "access to the Oracle iSupport program may not be licensed as Employee Users, but must be licensed as `" fullword ascii
    $s2 = "kdispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}