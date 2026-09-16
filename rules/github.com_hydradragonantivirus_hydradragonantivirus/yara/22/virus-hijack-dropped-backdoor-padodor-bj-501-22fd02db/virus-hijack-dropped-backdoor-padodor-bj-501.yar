rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_501 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_501.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c67b708e4e9af758a85c37f327515fc0d0f5e87fb4ab97c2b5a347983d82bd9"

  strings:
    $s1 = "Mactive employee population and not the number of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}