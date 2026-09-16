rule Virus_Hijack_Gen_Trojan_ShellObject_huZ_amBwvTb_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.huZ@amBwvTb_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f27cc2dab751bfaaf4c8dededc3f5806c86123122227cad176a64319034a6b6d"

  strings:
    $s1 = "!Error Download" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}