rule Virus_Hijack_Gen_Trojan_ShellObject_pyZ_aeWgNZc_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.pyZ@aeWgNZc_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "383a962c32f85f1524c8b337bacc668faed2a00246c4035fd800a8d74ad9297e"

  strings:
    $s1 = "hOpe<jl" fullword ascii
    $s2 = "\\[JOCK" fullword ascii
    $s3 = "F'(ArBA" fullword ascii
    $s4 = "GyPs#%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}