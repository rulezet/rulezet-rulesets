rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_99 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_99.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1705913bf48f86ca411e52067c986a924087981327291c209ab3a1ca1e5c475a"

  strings:
    $s1 = "If you want to find out more about academic soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}