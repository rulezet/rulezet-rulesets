rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aG5Bc5o_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "386a3c090e26b37e608d60b8ad0212efd5619a346590dc93773367acf7cebc20"

  strings:
    $s1 = "Text File, Or Html" fullword wide
    $s2 = "Image Formats" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}