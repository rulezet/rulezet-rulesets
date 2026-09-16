rule Trojan_Hooker_Win32_Floxif_A_20_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_20_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d3398100985204c475e0eb85c7308c54840165017a0c4dff131e3cc14ddef47"

  strings:
    $s1 = "opacate" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}