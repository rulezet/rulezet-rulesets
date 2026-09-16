rule sig_20160527_9c01ccd1f1dceb61125187dae9a47205 {
  meta:
    description = "datamaliciousorder - file 20160527_9c01ccd1f1dceb61125187dae9a47205.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bda1e26a20f9d2d419e9d01ae0f01d102d12cbed3e28ac49fdfd9b7d1226f57c"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aqmieoJUGRZ.length;i++)if(i%2==0)x.push(aqmieoJUGRZ[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}