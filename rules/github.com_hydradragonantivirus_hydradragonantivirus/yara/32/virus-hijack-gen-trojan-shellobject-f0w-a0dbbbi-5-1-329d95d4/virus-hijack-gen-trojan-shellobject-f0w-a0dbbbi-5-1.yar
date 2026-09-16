rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_a0DbbBi_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d53e109b070fac1b54219c4b5463505d90ad14c599e3dd8266246b6cc9ffabf8"

  strings:
    $s1 = "rundll32.exe \"%s\",main" fullword ascii
    $s2 = "!Taglwqsqnqclumsrmot be run in DOS mode." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}