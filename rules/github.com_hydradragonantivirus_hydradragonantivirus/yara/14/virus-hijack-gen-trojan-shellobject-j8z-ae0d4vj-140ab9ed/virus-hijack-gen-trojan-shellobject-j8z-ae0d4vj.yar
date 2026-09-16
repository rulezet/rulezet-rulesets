rule Virus_Hijack_Gen_Trojan_ShellObject_j8Z_ae0D4Vj {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.j8Z@ae0D4Vj.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2bf83ccfe681fd3cecb9a0109232bcd14b67b3ef70cc7900002e856c71ea6ad"

  strings:
    $s1 = "If you choose not to renew the membership, all rights to use the Pre`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}