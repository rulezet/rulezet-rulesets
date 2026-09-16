rule Trojan_Autorun_Trojan_GenericKD_72517131_149_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_149_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c6cf8e3ca64a87f6f9a5b1fd1ef2190ec2f7cc5ce8e88cf9ab320cfbf4b04a5"

  strings:
    $s1 = "F$User, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}