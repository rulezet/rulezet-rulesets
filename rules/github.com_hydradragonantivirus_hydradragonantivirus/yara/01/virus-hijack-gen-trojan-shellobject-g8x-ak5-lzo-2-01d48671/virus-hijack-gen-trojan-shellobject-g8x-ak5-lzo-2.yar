rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_aK5_lZo_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@aK5!lZo_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37011fed2beedc6da55b66f7ca9e35e5020e34123ce7b11ce63651e451e9d479"

  strings:
    $s1 = "pIky&ck" fullword ascii
    $s2 = "IUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}