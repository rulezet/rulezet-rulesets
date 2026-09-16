rule Virus_Hijack_Gen_Trojan_ShellObject_eGW_aCQuMlp_13_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eGW@aCQuMlp_13_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d603b1b6b142f27434225ab4a654dfc09483c07512a934c35edba25fcb7522d"

  strings:
    $s1 = "/#Last" fullword ascii
    $s2 = "Next]6" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}