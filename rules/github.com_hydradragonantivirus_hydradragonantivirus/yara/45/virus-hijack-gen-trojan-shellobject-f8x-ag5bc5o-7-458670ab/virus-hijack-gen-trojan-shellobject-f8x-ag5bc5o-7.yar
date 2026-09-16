rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aG5Bc5o_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c511d85e313e480ba95df11072b38098133fe848496ea9c20a97a25ba1153612"

  strings:
    $s1 = " hundred euros) in all purchase orders transacted" fullword ascii
    $s2 = "\"v%]*){sNEb" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}