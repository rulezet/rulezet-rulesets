rule Virus_Sysbot_Trojan_GenericKDZ_94923_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKDZ.94923_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8213d0307a1c3b96ed1e2b483140dab7110a5c7f8bec6b1a07fbed50c9ba321f"

  strings:
    $s1 = "Unbundled" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}