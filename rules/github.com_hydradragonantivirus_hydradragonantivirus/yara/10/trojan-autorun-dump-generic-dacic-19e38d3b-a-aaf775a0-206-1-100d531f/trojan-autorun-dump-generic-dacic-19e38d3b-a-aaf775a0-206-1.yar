rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_206_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_206_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5a25bde7c48f7b8f9fdcc2048e737d9427e2b944a66604df1a61229b397c722"

  strings:
    $s1 = "xpected multithread lock error" fullword wide
    $s2 = "  (fc_2): Linear(in_features=256, out_features=" fullword ascii
    $s3 = "  (fc_1): Linear(in_features=256, out_features=256, bias=True)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}