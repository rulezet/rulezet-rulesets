rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_aiqugi_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aiqugi_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8995429aaca71d06d0fb45d2190b74384c4249f453482cfbf17ce0bf18d12f9"

  strings:
    $s1 = "b4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}