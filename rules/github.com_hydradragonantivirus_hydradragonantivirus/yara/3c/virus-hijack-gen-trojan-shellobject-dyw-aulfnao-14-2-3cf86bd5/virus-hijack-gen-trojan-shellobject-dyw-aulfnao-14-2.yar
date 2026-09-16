rule Virus_Hijack_Gen_Trojan_ShellObject_dyW_auLFnao_14_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dyW@auLFnao_14_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4cdfc65f8db157b296679ddd05998942085d3f5aecc4974eb0a81abfb2b18543"

  strings:
    $s1 = "daSi Q" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}