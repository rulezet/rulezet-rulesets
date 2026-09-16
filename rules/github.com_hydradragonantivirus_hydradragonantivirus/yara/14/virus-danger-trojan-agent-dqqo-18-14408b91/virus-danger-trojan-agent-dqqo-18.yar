rule Virus_Danger_Trojan_Agent_DQQO_18 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Trojan.Agent.DQQO_18.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f64f6aca0273f1a26f46317b92d609958a00553d93614cf19c5ae9e84f7b2a1"

  strings:
    $s1 = "#authorized sources. Certain upgrades, support, and other services may be offered only to users of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}