rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aSZtDuk_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aSZtDuk_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f3edf9d954190069d624116c95a39ccde0db598fb7db1fddcdca820371b52fe"

  strings:
    $s1 = "lister" fullword wide
    $s2 = "Copyright Manocle 2011" fullword wide
    $s3 = "!This probram cannot be run in DOS mode." fullword ascii
    $s4 = "<track" fullword ascii
    $s5 = "LISTER Application" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}