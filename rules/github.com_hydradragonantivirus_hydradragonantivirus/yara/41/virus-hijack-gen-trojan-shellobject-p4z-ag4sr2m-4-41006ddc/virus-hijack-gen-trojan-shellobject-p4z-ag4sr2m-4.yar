rule Virus_Hijack_Gen_Trojan_ShellObject_p4Z_aG4Sr2m_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.p4Z@aG4Sr2m_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8289e062d1314c94bcf9ea89750089137edb08824a753975a27b7539772fd9b"

  strings:
    $s1 = "hthat party must agree that this agreement applies to the transfer and use of the software. You may not" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}