rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_a41FOHj_13 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@a41FOHj_13.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "066c5c5d8abdc6b26b04a1b6d7a74d5478444bd631acb910e4a25fa3002dd799"

  strings:
    $s1 = "c<ToiT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}