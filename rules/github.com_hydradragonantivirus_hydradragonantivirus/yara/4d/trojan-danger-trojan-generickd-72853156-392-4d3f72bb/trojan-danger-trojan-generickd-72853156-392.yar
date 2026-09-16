rule Trojan_Danger_Trojan_GenericKD_72853156_392 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_392.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5ee5d1a9f272828b0ceebb871bd5692c67be0bf79802e94ba6a68169007d944"

  strings:
    $s1 = "Windows Media Player.lnk.exe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}