rule Virus_Hijack_Trojan_GenericKDZ_98388_175 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_175.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a6709099253741608738a33838ed3e00e911d940ee2e5e46b6e24bdced5d74d"

  strings:
    $s1 = ":poEm}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}