rule Trojan_Danger_Trojan_GenericKD_72304918_24_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_24_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31b45c9f995e316325cc5813f522cef19607bd1b63f4921ced51d10dd0d4714d"

  strings:
    $s1 = "&Emust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}