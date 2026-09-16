rule Virus_Hijack_Gen_Trojan_ShellObject_i0Z_aiqugi_9_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Z@aiqugi_9_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e92cdffdb7a1dd4b7021c9c54d48abbd3e2b1280299410359f0bc78dd73bbd85"

  strings:
    $s1 = "SMB Share For DevelopmentFiles path" fullword wide
    $s2 = "Deleting SMB Share For DevelopmentFiles path" fullword wide
    $s3 = "Developer Tools Service" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}