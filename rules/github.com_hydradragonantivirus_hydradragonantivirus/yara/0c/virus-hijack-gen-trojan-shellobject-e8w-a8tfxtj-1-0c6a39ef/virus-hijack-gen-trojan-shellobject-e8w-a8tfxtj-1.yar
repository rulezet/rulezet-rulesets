rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_a8TFxTj_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@a8TFxTj_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b91bc9ea94113d851a74233f18849f580bda8783b65b829004b3363397a0da3f"

  strings:
    $s1 = "MetaLink has information on which products have been translated for the supported languages (http://metalink.oracle.c`" fullword ascii
    $s2 = "N\":NOuP$" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}