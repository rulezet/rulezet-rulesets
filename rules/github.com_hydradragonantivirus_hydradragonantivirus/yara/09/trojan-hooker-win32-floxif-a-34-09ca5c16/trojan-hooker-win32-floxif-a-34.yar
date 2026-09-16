rule Trojan_Hooker_Win32_Floxif_A_34 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_34.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3424fe4951bc1130dce352807e6b91adcbb6f725257d38ab144bb5e4f08519cd"

  strings:
    $s1 = "   <description>PAOT</description>" fullword ascii
    $s2 = "Hamous" fullword ascii
    $s3 = " IDlE$" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}