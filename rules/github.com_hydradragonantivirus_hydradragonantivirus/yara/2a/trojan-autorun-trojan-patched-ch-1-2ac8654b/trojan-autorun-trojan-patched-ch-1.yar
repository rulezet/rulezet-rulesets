rule Trojan_Autorun_Trojan_Patched_CH_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.Patched.CH_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97f9e9d9f99e36d2d8f94e9796fe1c0ad938d7c34e00bce0c9a07019ac40c1ee"

  strings:
    $s1 = "\"IRE_OLSA_V120103_Def_V122304 Page 1 of 11 " fullword ascii
    $s2 = "8!taSH" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}