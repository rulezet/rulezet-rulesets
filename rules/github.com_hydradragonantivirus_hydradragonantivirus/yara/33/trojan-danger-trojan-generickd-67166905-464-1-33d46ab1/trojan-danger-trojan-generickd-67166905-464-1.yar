rule Trojan_Danger_Trojan_GenericKD_67166905_464_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_464_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02bed924e76cdc5d3df607de782b95dc5616daa3a839f14f7ef4afb785255bb8"

  strings:
    $s1 = "O\"AXIl" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}