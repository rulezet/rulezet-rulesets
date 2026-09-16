rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_ayWIjmh_9_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@ayWIjmh_9_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0702c41fb38db75bace91785d4a18a0bb06338ea994ef52ab1a023554f719a0"

  strings:
    $s1 = " <rdf:Description about='uuid:6d39c6d2-21ce-11d7-9cf3-c01b0f5ad522'" fullword ascii
    $s2 = "  <xapMM:DocumentID>adobe:docid:photoshop:6d39c6c9-21ce-11d7-9cf3-c01b0f5ad522</xapMM:DocumentID>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}