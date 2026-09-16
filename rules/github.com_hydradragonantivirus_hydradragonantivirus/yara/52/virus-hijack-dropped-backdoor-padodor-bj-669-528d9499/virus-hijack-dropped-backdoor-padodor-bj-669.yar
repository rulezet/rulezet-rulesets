rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_669 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_669.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bcd8749888f4f18fcba5fe34da5fd50a68dfddb09936d908ae78cdd57d45062e"

  strings:
    $s1 = "8ALabor, a person is defined as an employee or con" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}