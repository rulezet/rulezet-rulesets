rule Virus_Hijack_Trojan_Agent_DQQO_219 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_219.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1505bff53269e7bea6365986a0abbfbd1ab1d07a94836f409a6915243acb005"

  strings:
    $s1 = "u&Professional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}