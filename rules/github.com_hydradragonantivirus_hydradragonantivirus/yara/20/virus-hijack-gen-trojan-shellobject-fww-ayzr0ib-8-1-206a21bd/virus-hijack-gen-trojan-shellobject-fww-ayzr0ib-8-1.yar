rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_ayzr0Ib_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@ayzr0Ib_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68f8a035625078cd245aeb8a45a7e6c106d3773a2be11b0c004a7207f6a55e34"

  strings:
    $s1 = "<description>Java(TM) SE jinfo process</description>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}