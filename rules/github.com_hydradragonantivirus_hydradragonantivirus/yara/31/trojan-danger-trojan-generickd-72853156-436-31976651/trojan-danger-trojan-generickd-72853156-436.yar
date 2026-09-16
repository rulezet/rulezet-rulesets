rule Trojan_Danger_Trojan_GenericKD_72853156_436 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_436.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28ef8931016a6cd51e00716ab146b59ea3197a477a54a46a611dd2a685d6e39f"

  strings:
    $s1 = ">?/>?w?p>@0>?oOp>@x?p>@pOsh" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}