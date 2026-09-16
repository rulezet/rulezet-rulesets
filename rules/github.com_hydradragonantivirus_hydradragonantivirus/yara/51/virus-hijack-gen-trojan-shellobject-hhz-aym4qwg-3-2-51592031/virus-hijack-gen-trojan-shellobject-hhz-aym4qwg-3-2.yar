rule Virus_Hijack_Gen_Trojan_ShellObject_hHZ_ayM4QWg_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.hHZ@ayM4QWg_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "123ebeca2dbfbc9072bced93fb77ff353cc6ac80340d1fb82690592263814b9b"

  strings:
    $s1 = "TOrSE)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}