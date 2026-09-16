rule Virus_Hijack_Trojan_GenericKDZ_103285_882 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_882.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "060b18ba38a28faf5763f8b26e019f3e1699f09657e460ba1d9a5f72ba6c1e91"

  strings:
    $s1 = "QBmicrosoft.com/office/backup. You may not distribute the backup copy of the software. You may use it" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}