rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_74_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_74_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23b5ee4e6a911ab8d2fcedcaed16a05949bb2958f456d7d24b7aa1fcd79deea1"

  strings:
    $s1 = "prepenial" fullword wide
    $s2 = "mooter" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}