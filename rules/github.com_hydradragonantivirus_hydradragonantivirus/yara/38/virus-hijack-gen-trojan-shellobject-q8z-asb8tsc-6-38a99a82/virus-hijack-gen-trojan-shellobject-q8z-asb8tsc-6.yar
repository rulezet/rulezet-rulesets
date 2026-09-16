rule Virus_Hijack_Gen_Trojan_ShellObject_q8Z_aSb8tSc_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aSb8tSc_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "420f69bf5af7b9909808c3106eddc035fcd590259a8b77959b28cb5d555d87a0"

  strings:
    $s1 = "ScYT*E" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}