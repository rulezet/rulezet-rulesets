rule Virus_Hijack_Gen_Trojan_ShellObject_uuZ_amBwvTb_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.uuZ@amBwvTb_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f955cc7c84253a1ad67ad8d2e5e23159e055a239daf92976b23395d85e9ae42e"

  strings:
    $s1 = "Copyright (c) 2002-2008 by Adobe Systems Incorporated.  All rights reserved." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}