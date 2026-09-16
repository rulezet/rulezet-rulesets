rule Trojan_Autorun_Trojan_GenericKD_72517131_70_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_70_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc19dc6e2b0e82806aefc6548080e22f1f70b061c679fc42936a293f26987eeb"

  strings:
    $s1 = ",(hundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}