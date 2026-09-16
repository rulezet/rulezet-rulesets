rule Virus_Hijack_Gen_Trojan_ShellObject_CwZ_amBwvTb_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.CwZ@amBwvTb_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ed91bb3ca25d779143417c9a3fbda694d044f0540a575c1c64feea06cbade35"

  strings:
    $s1 = "|).`DoUr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}