rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_ayzr0Ib_15_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@ayzr0Ib_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "206b543fb6d1e7654551e78037d72bc4b85529e3b7e6b2cb0f5f44874fc0ef6a"

  strings:
    $s1 = "<description>Java(TM) SE jrunscript process</description>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}