rule Virus_Hijack_Backdoor_Hangup_B_131 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_131.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9819f978ba69148a866a21ad604fd24678f13d53be8cf405aed8c0d6b88b8c4d"

  strings:
    $s1 = "xsoftware manually by Internet or telephone. In either case, Internet and telephone service charges may" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}