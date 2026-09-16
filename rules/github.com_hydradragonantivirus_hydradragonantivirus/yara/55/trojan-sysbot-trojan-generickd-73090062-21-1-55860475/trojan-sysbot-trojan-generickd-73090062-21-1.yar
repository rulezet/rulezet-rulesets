rule Trojan_Sysbot_Trojan_GenericKD_73090062_21_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Sysbot_Trojan.GenericKD.73090062_21_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1235d7431c0e717ca06fd6bb29a479b973ceaecc064d4b7438f897d551ee0b95"

  strings:
    $s1 = "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.34.31938" fullword wide
    $s2 = "Microsoft Visual C++ 2015-2022 Redistributable (x64) - 14.34.3193" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}