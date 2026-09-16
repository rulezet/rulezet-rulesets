rule Trojan_Autorun_Gen_Heur_Mint_Murphy_3_33_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Heur.Mint.Murphy.3_33_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86525375c1586935abfd512a058e544602287452e46589757f9606ee5437929c"

  strings:
    $s1 = "(sILt{" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}