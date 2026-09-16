rule Virus_Hijack_Trojan_Agent_DQQO_151_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_151_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d4d2136ae54d4f76136bd630edc2acb6ed92c816e028c489c620ec08bbe00d1"

  strings:
    $s1 = "w}sABe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}