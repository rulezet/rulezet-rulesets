rule Virus_Hijack_Gen_Trojan_ShellObject_PuZ_amBwvTb_15 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.PuZ@amBwvTb_15.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec82344a28a8c56d33339fc36b5b4cfadb4a2a41a0e0d5c44c89ca07ccef2388"

  strings:
    $s1 = ";PeNSy" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}