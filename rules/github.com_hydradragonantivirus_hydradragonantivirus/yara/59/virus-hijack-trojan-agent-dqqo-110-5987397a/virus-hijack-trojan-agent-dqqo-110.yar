rule Virus_Hijack_Trojan_Agent_DQQO_110 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_110.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b09465a34553dd713a7c2982e3e23deab60c17b2e735cc2def255d5e35e4c7a"

  strings:
    $s1 = "gyou received the software, and also any Microsoft updates, supplements, and services for the software," fullword ascii
    $s2 = "FOsH O" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}