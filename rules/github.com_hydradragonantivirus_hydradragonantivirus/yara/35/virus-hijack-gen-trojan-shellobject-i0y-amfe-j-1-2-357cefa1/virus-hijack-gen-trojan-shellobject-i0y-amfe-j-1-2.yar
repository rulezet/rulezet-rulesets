rule Virus_Hijack_Gen_Trojan_ShellObject_i0Y_amFE__j_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Y@amFE@@j_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "860f619b895af5b1af4390ad7366bfa5f62171704120063ab76632381e93b997"

  strings:
    $s1 = "if exist \"%s\" goto runagain" fullword ascii
    $s2 = "Media PlayGCO" fullword ascii
    $s3 = "56,golf u" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}