rule Virus_Hijack_Backdoor_Hangup_B_222 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_222.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a30ca50f9ba68a664827b804fd426ff71fb6687a89f963db250ab7f2efa4660"

  strings:
    $s1 = "oTrade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data, information," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}