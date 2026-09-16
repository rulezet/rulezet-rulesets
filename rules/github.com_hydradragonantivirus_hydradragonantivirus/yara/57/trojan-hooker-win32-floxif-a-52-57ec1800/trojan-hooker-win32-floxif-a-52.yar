rule Trojan_Hooker_Win32_Floxif_A_52 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_52.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d173ada23b95962384760795454329fe29c719a2ddea50bcfcf69750045006f"

  strings:
    $s1 = "BIT COMPUTER CO., LTD.0" fullword ascii
    $s2 = "BIT COMPUTER CO., LTD.1" fullword ascii
    $s3 = "Action@QA" fullword ascii
    $s4 = "Font<ZC" fullword ascii
    $s5 = "Management Team10" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}