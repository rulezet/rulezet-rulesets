rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_a0DbbBi {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf3c1aecea0a0a0afb4df8776b799cae92755a328a19f126641ab5ea314da155"

  strings:
    $s1 = "access to the Oracle iSupport program may not be licensed as Employee Users, but must be licensed as `" fullword ascii
    $s2 = "Cdispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}