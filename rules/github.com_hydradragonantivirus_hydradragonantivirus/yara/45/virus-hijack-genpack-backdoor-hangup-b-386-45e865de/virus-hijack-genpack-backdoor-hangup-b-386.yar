rule Virus_Hijack_GenPack_Backdoor_Hangup_B_386 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_386.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c78caf272c49bf1a983f94dc5fd8982688d36d8c5687535e877c7fc2afa4474"

  strings:
    $s1 = "rTrade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data, information," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}