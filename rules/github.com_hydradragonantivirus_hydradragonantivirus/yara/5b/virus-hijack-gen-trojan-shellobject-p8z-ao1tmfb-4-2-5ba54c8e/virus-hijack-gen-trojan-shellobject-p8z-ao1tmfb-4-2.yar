rule Virus_Hijack_Gen_Trojan_ShellObject_p8Z_aO1tmfb_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.p8Z@aO1tmfb_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8b7b1cd59c432301b135ad2ceac1872d9eee0d77ff5a5c20cff2e9129d9b22c"

  strings:
    $s1 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1)" fullword ascii
    $s2 = "BOGY'S GAME ENGINE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}