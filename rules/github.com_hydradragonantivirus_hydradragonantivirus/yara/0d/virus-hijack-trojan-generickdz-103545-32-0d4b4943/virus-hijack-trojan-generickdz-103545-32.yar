rule Virus_Hijack_Trojan_GenericKDZ_103545_32 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_32.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30ca1252cc280522266eb1dff02ea1ad945e0b89300c0adb331ab2e62bdfe221"

  strings:
    $s1 = "www.oracle.com/education/oln/index.html, and may be updated by Oracle from time to time with`" fullword ascii
    $s2 = "Csoftware features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}