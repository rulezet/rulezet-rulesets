rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_auLSMIo_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@auLSMIo_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4be61e3bd286e70647d89e3dd74224dbf8765d72099154ef5aacce0aed49f426"

  strings:
    $s1 = "KERN`L32.d" fullword ascii
    $s2 = "Copyright  DhustTrers" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}