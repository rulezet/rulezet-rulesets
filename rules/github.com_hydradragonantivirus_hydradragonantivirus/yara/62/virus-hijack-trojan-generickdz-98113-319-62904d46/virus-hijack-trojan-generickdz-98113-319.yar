rule Virus_Hijack_Trojan_GenericKDZ_98113_319 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_319.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8656027bd9ce05cc977f3147428b90350337ecfc5e8444f36fd474f45144a0f7"

  strings:
    $s1 = "Cstring too long" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}