rule Virus_Hijack_Gen_Trojan_ShellObject_i0Y_amFE__j_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Y@amFE@@j_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b778fac66bfe7f42204896cdd6fb392be44d9d086fabba0df60e0d3ceb513da4"

  strings:
    $s1 = "R;;dIbS" fullword ascii
    $s2 = "8`SKuN" fullword ascii
    $s3 = "AlfA)~" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}