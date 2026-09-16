rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_a0DbbBi_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31aee5620a8f06745c44611f0259ea72b8cd58c13bd24e1336f1e65f880343c3"

  strings:
    $s1 = "\":dispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}