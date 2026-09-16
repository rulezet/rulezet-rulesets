rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aa9T7Ob_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f07da15935f17fc875ed5bbe7ff81290fbe0660bb4ef1ae75e3bfd113172f9f"

  strings:
    $s1 = "_hundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}