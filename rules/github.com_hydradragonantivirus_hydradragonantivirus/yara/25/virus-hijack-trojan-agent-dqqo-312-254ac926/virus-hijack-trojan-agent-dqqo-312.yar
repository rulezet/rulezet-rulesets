rule Virus_Hijack_Trojan_Agent_DQQO_312 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_312.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a59cb73bfa92492553a5e84562e38ac91138c51d85e01bd49c045ed7a51810e8"

  strings:
    $s1 = "}orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}