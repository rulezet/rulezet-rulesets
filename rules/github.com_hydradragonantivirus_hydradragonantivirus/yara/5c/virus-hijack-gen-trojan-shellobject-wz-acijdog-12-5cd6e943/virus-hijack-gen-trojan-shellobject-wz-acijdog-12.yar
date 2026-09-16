rule Virus_Hijack_Gen_Trojan_ShellObject__WZ_aCIJdog_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.@WZ@aCIJdog_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e70f9b7a35c2d8dfae251a8233d579bcedcf5bf2d12ba749094ee2ed379705f"

  strings:
    $s1 = "tAXy)AX" fullword ascii
    $s2 = "diva>9" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}