rule Trojan_Danger_Trojan_GenericKD_35816276_3 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.35816276_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a36390c5f900aed296a182bfae70bc5d19bf49ccb3867681808a1fc42e0001f"

  strings:
    $s1 = "ymust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}