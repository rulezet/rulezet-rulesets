rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_269_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_269_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c7096e55eacc03393e8b8133a22a201c71140d4a265c81337fb94acecaa2d09"

  strings:
    $s1 = "|uz#<*doLa" fullword ascii
    $s2 = "wK!COlY" fullword ascii
    $s3 = "nb&wIlK" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}