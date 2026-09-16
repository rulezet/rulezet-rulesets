rule Trojan_Danger_Trojan_GenericKD_72597336_32_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72597336_32_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ff2fd5f1419745f8c454ef364ceb9f08da72aaa7bef50f83962a2f6a935cf09"

  strings:
    $s1 = "lWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}