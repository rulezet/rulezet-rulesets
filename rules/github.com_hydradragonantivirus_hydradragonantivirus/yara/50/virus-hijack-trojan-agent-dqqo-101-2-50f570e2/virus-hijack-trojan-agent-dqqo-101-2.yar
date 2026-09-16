rule Virus_Hijack_Trojan_Agent_DQQO_101_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_101_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a290ae17ae06fdddc6d4a461452d54830d8108b623f2ff701ed6acc840d0be64"

  strings:
    $s1 = "%(goer" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}