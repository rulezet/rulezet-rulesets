rule Virus_Hijack_Gen_Trojan_ShellObject_u8Z_aOGzovi_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aOGzovi_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a82360e771d90634df91a2353c491f84578b447f3b980aae41e488ea4d1fb7de"

  strings:
    $s1 = "pUcE Software" fullword wide
    $s2 = "Enjoy !" fullword wide
    $s3 = "!'%s' is not a valid integer value\"'%s' is not a valid currency value!'%g' is not a valid date and timeInvalid argument to tim" wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}