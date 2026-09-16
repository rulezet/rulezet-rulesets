rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_230_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_230_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3e4b2ae64c6ab01ac39ec805cc8a446a00c0add510165b83d48d90d94ce73be"

  strings:
    $s1 = "informational links in this agreement. The links containing terms that bind you and`" fullword ascii
    $s2 = "mZ2013 software. For your convenience, we" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}