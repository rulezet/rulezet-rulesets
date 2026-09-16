rule Virus_Hijack_Gen_Trojan_ShellObject_f4X_aqH1LVc {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f4X@aqH1LVc.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f676c131c04f74cb8d3e88b943584af112cb1bd6ecbeacc02496bb0c03108e5"

  strings:
    $s1 = "9must be a Qualified Educational User to use software marked as " fullword ascii
    $s2 = "tf#creW" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}