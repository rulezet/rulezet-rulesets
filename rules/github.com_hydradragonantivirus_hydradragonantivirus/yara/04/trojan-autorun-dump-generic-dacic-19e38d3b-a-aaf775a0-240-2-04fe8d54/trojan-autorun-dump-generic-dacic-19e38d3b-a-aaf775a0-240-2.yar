rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_240_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_240_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9db944d987cd0d1ca6597246d083faa957177d40eb0691b9a06ec002b98092f4"

  strings:
    $s1 = "nAAm.*" fullword ascii
    $s2 = "l 2 [besa" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}