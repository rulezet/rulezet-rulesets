rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_783 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_783.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ffb79d027a90674e42443073303cbd89a5e177cf14cafded1b80a1dec37624b"

  strings:
    $s1 = "X)Microsoft Ireland Operations Limited makes the l" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}