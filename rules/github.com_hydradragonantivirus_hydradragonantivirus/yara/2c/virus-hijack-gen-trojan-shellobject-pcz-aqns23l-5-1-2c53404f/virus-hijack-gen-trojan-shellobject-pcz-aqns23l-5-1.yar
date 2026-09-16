rule Virus_Hijack_Gen_Trojan_ShellObject_PCZ_aqns23l_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.PCZ@aqns23l_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ce08dc9f7fcf2e2e91d29372349c18342f60be52980ca774b897a54167af204"

  strings:
    $s1 = "D`warT" fullword ascii
    $s2 = "]{flEX" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}