rule Trojan_Danger_Trojan_GenericKD_67166905_485 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_485.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "add36c70fdecd8901c439690906ea9f387ecb084b713bf5a337732cb0eaef984"

  strings:
    $s1 = "Compile Script to .exe (x64).lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}