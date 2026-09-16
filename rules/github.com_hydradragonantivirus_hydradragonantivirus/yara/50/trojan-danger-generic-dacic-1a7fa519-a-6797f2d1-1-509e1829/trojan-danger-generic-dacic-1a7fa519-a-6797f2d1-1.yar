rule Trojan_Danger_Generic_Dacic_1A7FA519_A_6797F2D1_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Generic.Dacic.1A7FA519.A.6797F2D1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ccfa84901352820f90c17f1a383249e6ec0b7e5eaf3b86974fb1bf7349766b6"

  strings:
    $s1 = "MXmust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}