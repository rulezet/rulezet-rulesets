rule sig_20160527_73f332aa897387fb12c0127cec591fd0 {
  meta:
    description = "datamaliciousorder - file 20160527_73f332aa897387fb12c0127cec591fd0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e9d86bcad6629f03010fe66f34555f9a9053e8591734e4f704147bc68da91f0"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aReAW3IGZ.length;i++)if(i%2==0)x.push(aReAW3IGZ[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}