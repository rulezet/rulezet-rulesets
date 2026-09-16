rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aa9T7Ob_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aa9T7Ob_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "99341669b6a3b0c5bf4e8c35141cf0142c44719419a737aaa9b5ec8323cb0d57"

  strings:
    $s1 = "nhundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}