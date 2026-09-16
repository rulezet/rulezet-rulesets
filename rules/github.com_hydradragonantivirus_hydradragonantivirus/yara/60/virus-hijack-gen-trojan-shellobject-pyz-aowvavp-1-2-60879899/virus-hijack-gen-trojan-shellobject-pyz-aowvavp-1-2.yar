rule Virus_Hijack_Gen_Trojan_ShellObject_pyZ_aOWVavp_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.pyZ@aOWVavp_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f91ade6a1095f656d2dd5bbb7c0722a5b41acd808e12039dc0d2b9a9bde5801"

  strings:
    $s1 = "dARE#p" fullword ascii
    $s2 = "\"MuZZ%Z" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}