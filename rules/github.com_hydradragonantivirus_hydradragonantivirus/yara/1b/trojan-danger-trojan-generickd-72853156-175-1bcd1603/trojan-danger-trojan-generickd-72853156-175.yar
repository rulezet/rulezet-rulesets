rule Trojan_Danger_Trojan_GenericKD_72853156_175 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_175.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "abf4653e6ed0ff5c2ee3cc163209fab6d85637d35e80a8cb354b5f96048e8200"

  strings:
    $s1 = "ecad`_b^^" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}