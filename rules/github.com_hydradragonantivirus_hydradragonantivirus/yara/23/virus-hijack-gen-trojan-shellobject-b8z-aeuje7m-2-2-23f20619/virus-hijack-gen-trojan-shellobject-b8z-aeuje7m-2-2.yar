rule Virus_Hijack_Gen_Trojan_ShellObject_B8Z_aeuJE7m_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.B8Z@aeuJE7m_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc163865fdab8a110f39e1e924f92ce4dda8a1394867a30efdf0da9fed730cc2"

  strings:
    $s1 = "aNte\"" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}