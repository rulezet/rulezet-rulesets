rule Virus_Hijack_Gen_Trojan_ShellObject_PuZ_amBwvTb_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.PuZ@amBwvTb_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2bc933758e6b998f34985af206fe43613cef6f654b77e1a864b9c659bf09ef29"

  strings:
    $s1 = "ewRy(@<" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}