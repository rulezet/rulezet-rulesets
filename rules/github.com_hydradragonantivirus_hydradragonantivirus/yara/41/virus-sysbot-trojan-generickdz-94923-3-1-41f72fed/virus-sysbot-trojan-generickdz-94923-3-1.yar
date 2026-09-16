rule Virus_Sysbot_Trojan_GenericKDZ_94923_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKDZ.94923_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cab51142b57e8d493e2841b243622763b55d9dac25c6a63140b1e0002d14adb6"

  strings:
    $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*)
}