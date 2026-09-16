rule Virus_Hijack_Trojan_GenericKDZ_103545_26 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_26.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "726228933394bc73b7799d2a94754f25e89ad5f82d95842391a10826295520ec"

  strings:
    $s1 = "/)software features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}