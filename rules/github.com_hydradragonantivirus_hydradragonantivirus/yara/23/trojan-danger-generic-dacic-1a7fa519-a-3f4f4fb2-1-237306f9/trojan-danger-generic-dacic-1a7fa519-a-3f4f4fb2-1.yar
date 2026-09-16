rule Trojan_Danger_Generic_Dacic_1A7FA519_A_3F4F4FB2_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Generic.Dacic.1A7FA519.A.3F4F4FB2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "179e7af8ccfb1feb0096c333a3c442d1b98bfdd57061987e565f2016d12d2c7c"

  strings:
    $s1 = "Emicrosoft.com/office/backup. You may not distribute the backup copy of the software. You may use it" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}