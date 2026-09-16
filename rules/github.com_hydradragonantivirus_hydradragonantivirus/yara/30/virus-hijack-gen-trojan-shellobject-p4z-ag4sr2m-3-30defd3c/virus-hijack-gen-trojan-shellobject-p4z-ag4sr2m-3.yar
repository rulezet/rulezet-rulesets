rule Virus_Hijack_Gen_Trojan_ShellObject_p4Z_aG4Sr2m_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.p4Z@aG4Sr2m_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bcce606a25be0e705915a2dd7f357bbba98cb5003009483daadeb572dd43bf3"

  strings:
    $s1 = "ithat party must agree that this agreement applies to the transfer and use of the software. You may not" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}