rule Virus_Hijack_Trojan_Agent_DQQO_282 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_282.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dfbc9d75f03754788bb15a36e276de2575b1b18236011ff8c4657b52a9fc7a60"

  strings:
    $s1 = "!sINh  " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}