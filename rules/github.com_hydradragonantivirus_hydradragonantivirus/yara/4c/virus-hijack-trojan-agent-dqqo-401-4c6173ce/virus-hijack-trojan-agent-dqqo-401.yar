rule Virus_Hijack_Trojan_Agent_DQQO_401 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_401.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b417ae139560da2838c38f503d3bf3ddeb659137ffb3ebdee2bd59357eef1850"

  strings:
    $s1 = "Kautomatically sign you into the software using the same Microsoft account. This allows you to store and" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}