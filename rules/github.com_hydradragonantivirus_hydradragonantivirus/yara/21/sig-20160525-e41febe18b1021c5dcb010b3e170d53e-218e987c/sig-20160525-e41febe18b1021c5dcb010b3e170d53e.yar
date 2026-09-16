rule sig_20160525_e41febe18b1021c5dcb010b3e170d53e {
  meta:
    description = "datamaliciousorder - file 20160525_e41febe18b1021c5dcb010b3e170d53e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6dcfcfcf778970a4a4622b83af59413214abb136ba018250d0d21d1435be8c9"

  strings:
    $s1 = "c\"[imb = gsmc rav;\"ki5B\" = imb rav\\n;\"ce2x\\\\\" = dnenoisillocc rav\\n;)1(]\"tAra\"+\"86x\\\\\"+\"c\"[suidarelcitrapc = mc" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}