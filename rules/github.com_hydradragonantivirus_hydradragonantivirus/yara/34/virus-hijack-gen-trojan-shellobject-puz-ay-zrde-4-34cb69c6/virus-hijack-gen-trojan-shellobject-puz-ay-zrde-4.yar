rule Virus_Hijack_Gen_Trojan_ShellObject_puZ_ay_ZRde_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.puZ@ay!ZRde_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c41ef9a5675724b5be29fe321db8606465ef83170c5ec83b676cee0887bd93f"

  strings:
    $s1 = "A@*YilL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}