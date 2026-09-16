rule Trojan_Danger_Trojan_GenericKD_72853156_603 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_603.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e583349b6e4d57e5fddbad0680cdae03481e58a7f4791b357f6a4d48d77934bf"

  strings:
    $s1 = "p{wusp" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}