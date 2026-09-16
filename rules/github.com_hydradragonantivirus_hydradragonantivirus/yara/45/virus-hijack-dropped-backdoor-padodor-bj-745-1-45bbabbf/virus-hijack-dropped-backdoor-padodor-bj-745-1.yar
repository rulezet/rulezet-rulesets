rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_745_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_745_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a1ec1572383a8b600bab9abffd5039ec76127f4927a3e33e044abfe06fc8d0a"

  strings:
    $s1 = ";imMIt" fullword ascii
    $s2 = "foNS<," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}