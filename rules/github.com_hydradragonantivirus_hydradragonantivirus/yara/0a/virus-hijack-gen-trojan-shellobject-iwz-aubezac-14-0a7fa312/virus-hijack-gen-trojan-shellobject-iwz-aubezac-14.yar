rule Virus_Hijack_Gen_Trojan_ShellObject_iWZ_auBEZAc_14 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.iWZ@auBEZAc_14.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e01c8175056f646ff9c046e8d8aa3011494a211fbb03cf72c4cdc82e4093205"

  strings:
    $s1 = "hautomatically sign you into the software using the same Microsoft account. This allows you to store and" fullword ascii
    $s2 = "RIND` " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}