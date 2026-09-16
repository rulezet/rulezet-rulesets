rule Virus_Hijack_Trojan_GenericKDZ_105924_18_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_18_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ee0aa87e2eb018ddaccc221e14efa2f2b612f139b024143670bc45dda466fcf"

  strings:
    $s1 = "KERN`L32.dql" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}