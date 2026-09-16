rule sig_20160525_2c7e3f83d1cab7dee1d0285c720eb9a2 {
  meta:
    description = "datamaliciousorder - file 20160525_2c7e3f83d1cab7dee1d0285c720eb9a2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f050f3ddb5195c97096ee407636b86e244a462d92ce69a38f8cd59679bca0bd5"

  strings:
    $s1 = "darg[tpircSW = gsmb rav    \\n{\\n)tsilslianbmuhtoa(/*  rcx nUk xXf */ gsm noitcnuf\\n\\n\\n;}\\n};eslaf nruter{" fullword ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}