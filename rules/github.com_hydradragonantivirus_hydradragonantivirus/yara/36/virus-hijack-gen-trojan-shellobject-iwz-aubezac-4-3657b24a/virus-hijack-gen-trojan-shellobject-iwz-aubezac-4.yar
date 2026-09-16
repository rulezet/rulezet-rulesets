rule Virus_Hijack_Gen_Trojan_ShellObject_iWZ_auBEZAc_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.iWZ@auBEZAc_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd0681c20ca369d3b8e511b29bf6ad85553e526d7da27136f43de3f07d495185"

  strings:
    $s1 = "6automatically sign you into the software using the same Microsoft account. This allows you to store and" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}