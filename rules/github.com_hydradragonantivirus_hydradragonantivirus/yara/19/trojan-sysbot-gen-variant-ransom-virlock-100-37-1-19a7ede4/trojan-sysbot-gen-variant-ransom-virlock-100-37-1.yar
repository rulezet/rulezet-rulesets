rule Trojan_Sysbot_Gen_Variant_Ransom_VirLock_100_37_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Sysbot_Gen.Variant.Ransom.VirLock.100_37_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79b5b9c40e8b79eeb21c500bfdfb327e969826fa9a324f268b0d852c42c934d1"

  strings:
    $s1 = "Interactive Ruby.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}