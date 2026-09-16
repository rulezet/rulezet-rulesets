rule Trojan_Autorun_Trojan_GenericKD_72517131_264 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_264.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ab420428d51bafe98f31d075fa8435bf435e034fade08cb540119a0e49031b96"

  strings:
    $s1 = "K%User, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}