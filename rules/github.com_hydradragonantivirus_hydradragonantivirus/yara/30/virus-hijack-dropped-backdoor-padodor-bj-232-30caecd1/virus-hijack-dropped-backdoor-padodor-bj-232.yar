rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_232 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_232.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d6d7eb0a3546c2fae6eac4dcda6667c9cc564069ea1b51ca2390049cc63908e"

  strings:
    $s1 = "7must be a Qualified Educational User to use soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}