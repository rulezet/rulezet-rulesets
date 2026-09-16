rule Trojan_Autorun_Trojan_GenericKD_72517131_16_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_16_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "255ab738d1ad983bd5402bd015dc095866c785542c113ddbc2f0cb01cf888311"

  strings:
    $s1 = "KUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}