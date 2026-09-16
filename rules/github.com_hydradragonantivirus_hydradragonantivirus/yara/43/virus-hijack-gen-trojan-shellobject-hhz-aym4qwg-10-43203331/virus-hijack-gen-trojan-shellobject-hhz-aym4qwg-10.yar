rule Virus_Hijack_Gen_Trojan_ShellObject_hHZ_ayM4QWg_10 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.hHZ@ayM4QWg_10.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "452fb3f4d6092396467a9b75b3f1ff919379367446342b3b3aa9395ac17b71f5"

  strings:
    $s1 = "Rich!l" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}