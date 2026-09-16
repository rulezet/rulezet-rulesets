rule Virus_Hijack_Gen_Trojan_ShellObject_iuZ_aiy413e_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.iuZ@aiy413e_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c636b64e9d71e86c7e72f3fe22ce6c116a841ca801e56a08331ef38e55df581b"

  strings:
    $s1 = "KNAB`$%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}