rule Virus_Hijack_Trojan_GenericKDZ_103285_565 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_565.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cba1eb5937abed5181aa4c3a84e846d0495db0f396c0a7ae1375f4aa2417b5d4"

  strings:
    $s1 = "eEa neutral arbitrator, whose decision will be final except for a limited right of appeal under the Federal" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}