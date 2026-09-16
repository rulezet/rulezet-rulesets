rule Trojan_Danger_Trojan_GenericKD_72677122_92 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_92.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7306884b30241b0dfe48ff1e77e2544ac67092ee674ac55b26f180b2520f7473"

  strings:
    $s1 = "TRap?<RRRRRRnS__R" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}