rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_75 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_75.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd8ae677420d624058e79c6ddcae2366b94c82121d052e985cdcac839f2768e5"

  strings:
    $s1 = "\"c<KIsT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}