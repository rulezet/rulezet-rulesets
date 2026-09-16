rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_155_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_155_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf9ed65e92c962d8d587548a301d08d439ffe8a1d5aada0b027707621b8cf141"

  strings:
    $s1 = "LOuP]SuP]Iq" fullword ascii
    $s2 = "Z^<PLUd" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}