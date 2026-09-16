rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_21_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_21_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a190ce097b4b9590f1ba25641da35e488b0a73e17f4ae3d287608310ab39fe78"

  strings:
    $s1 = "support@amcert.net0" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}