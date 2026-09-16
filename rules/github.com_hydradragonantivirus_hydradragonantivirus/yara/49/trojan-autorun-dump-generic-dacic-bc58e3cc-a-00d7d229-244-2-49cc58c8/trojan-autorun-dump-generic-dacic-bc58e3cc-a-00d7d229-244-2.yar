rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_244_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_244_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "169b12e940a9053a20740f047d0389e0f83816ff5d97547b36cd008a2a12ecc7"

  strings:
    $s1 = "Secure Git credential helper for Windows, by Microsoft. https://github.com/Microsoft/Git-Credential-Manager-for-Windows" fullword wide
    $s2 = "Adobe Pdf Reader" fullword wide
    $s3 = "pdf reader" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}