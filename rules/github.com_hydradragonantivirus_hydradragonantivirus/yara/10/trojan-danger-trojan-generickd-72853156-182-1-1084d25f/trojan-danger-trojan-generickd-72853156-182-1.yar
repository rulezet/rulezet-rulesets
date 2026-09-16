rule Trojan_Danger_Trojan_GenericKD_72853156_182_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_182_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b324e46b6328fee96bd4c8f54a9457efad28ee5c81cf1cf4db20965928c71fc"

  strings:
    $s1 = "aLMA%{" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}