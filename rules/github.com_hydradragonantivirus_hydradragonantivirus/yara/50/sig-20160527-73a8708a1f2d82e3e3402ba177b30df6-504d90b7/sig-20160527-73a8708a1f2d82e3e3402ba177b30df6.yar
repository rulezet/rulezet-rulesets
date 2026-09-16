rule sig_20160527_73a8708a1f2d82e3e3402ba177b30df6 {
  meta:
    description = "datamaliciousorder - file 20160527_73a8708a1f2d82e3e3402ba177b30df6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1bb6dcfb15115ffd592e94a3180e2799706cadfe873540c163d1108f4c0ddff7"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<akWoiRK.length;i++)if(i%2==0)x.push(akWoiRK[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}