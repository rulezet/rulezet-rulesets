rule Virus_Hijack_Gen_Trojan_ShellObject_p4Z_aG4Sr2m_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.p4Z@aG4Sr2m_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8db919943f22c6374c3f64c3b0f152da366bc0c58e423381a744e855ccb8d854"

  strings:
    $s1 = "Runtime Check, Version 1.0" fullword wide
    $s2 = "Runtime Check" fullword wide
    $s3 = "About Installer" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}