rule Trojan_Hooker_Win32_Floxif_A_3_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8eeb6e09469f591fd62e26bf329aebcb76e6797675531427df23a0fc13aedeb8"

  strings:
    $s1 = "FILE FOLDER*" fullword ascii
    $s2 = "?sOMA%#R60" fullword ascii
    $s3 = "@Clean" fullword ascii
    $s4 = "5t Visual Audio\\1C'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}