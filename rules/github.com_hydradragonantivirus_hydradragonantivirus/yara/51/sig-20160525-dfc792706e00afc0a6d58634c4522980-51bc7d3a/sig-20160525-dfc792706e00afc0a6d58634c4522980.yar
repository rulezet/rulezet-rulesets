rule sig_20160525_dfc792706e00afc0a6d58634c4522980 {
  meta:
    description = "datamaliciousorder - file 20160525_dfc792706e00afc0a6d58634c4522980.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ebd013d939a988cbc000bf1afd3337df35cbc2fa45b9089a44afd3bf9d7ea144"

  strings:
    $s1 = " rav\\n;\"rf2x\\\\\" = keppelg rav\\n;)0(]\"tAra\"+\"86x\\\\\"+\"c\"[gedotdarg = ecapsetihwxelfg rav;\"GVf\" = gedotdarg rav\\n;" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}