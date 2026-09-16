rule Virus_Hijack_Trojan_Agent_DQQO_41 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_41.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12f1c23c38351cf2ddac181884195096811b3781e2f3dc5aa9694cd8011ed4f4"

  strings:
    $s1 = "+[whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}