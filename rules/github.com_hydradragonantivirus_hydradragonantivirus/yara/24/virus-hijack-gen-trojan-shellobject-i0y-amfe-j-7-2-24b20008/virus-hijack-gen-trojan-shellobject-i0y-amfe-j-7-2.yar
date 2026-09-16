rule Virus_Hijack_Gen_Trojan_ShellObject_i0Y_amFE__j_7_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Y@amFE@@j_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e7013e13a2de19f277456cc67708233eca1ed9d62a65122a0e62dd418089c36"

  strings:
    $s1 = "INOSIN" fullword ascii
    $s2 = "IN{pINO" fullword ascii
    $s3 = "INOsIN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}