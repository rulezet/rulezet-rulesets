rule Virus_Hijack_Gen_Trojan_ShellObject_i0Z_aiqugi_16_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Z@aiqugi_16_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b228556635f6aff2b0bac25a874d33319ef7f952afe377b9f5c2fbbccafb013"

  strings:
    $s1 = "zG#)gRit" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}