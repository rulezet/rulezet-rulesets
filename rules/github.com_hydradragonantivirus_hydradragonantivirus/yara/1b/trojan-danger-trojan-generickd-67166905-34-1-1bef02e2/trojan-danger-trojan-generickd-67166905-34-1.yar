rule Trojan_Danger_Trojan_GenericKD_67166905_34_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_34_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78f0fc3c55829a06439bee749306462bae87f8ebad769b10ceb4bf7eb21ff9a2"

  strings:
    $s1 = "#@A* @A* @A* @A* @A* @A* @A= @A= @A= @A= @A= @A= @A= @A= @AlLY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}