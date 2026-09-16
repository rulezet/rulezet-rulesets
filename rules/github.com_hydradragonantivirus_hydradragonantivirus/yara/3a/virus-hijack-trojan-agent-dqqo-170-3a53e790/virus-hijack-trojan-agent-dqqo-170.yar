rule Virus_Hijack_Trojan_Agent_DQQO_170 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_170.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5165b89496926ce8c252148145a89f513e2104476dc5345b984614b72e6a4d7"

  strings:
    $s1 = "Rwhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}