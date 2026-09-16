rule Virus_Hijack_Gen_Trojan_ShellObject_dWW_aOfWMFe_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dWW@aOfWMFe_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5236cfffaeb1e80fe527d7b3a7aaecf17dcedec585b63c528bbddd56342e73dc"

  strings:
    $s1 = "Copyright (C) 2014 Gydftgfefef" fullword wide
    $s2 = "Copyright 2014 QnotrLwide" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}