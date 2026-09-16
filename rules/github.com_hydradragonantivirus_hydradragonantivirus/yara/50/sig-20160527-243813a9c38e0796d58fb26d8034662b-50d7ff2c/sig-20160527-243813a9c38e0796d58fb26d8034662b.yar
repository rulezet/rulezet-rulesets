rule sig_20160527_243813a9c38e0796d58fb26d8034662b {
  meta:
    description = "datamaliciousorder - file 20160527_243813a9c38e0796d58fb26d8034662b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "364a32be16e8b39b84a2cc1252d7fd444dc8784fc43b7eb9fdae48edcae3af3d"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a0Aix6DItF.length;i++)if(i%2==0)x.push(a0Aix6DItF[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}