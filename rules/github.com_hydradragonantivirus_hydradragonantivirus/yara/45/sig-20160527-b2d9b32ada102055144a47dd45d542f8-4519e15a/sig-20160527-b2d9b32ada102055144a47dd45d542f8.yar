rule sig_20160527_b2d9b32ada102055144a47dd45d542f8 {
  meta:
    description = "datamaliciousorder - file 20160527_b2d9b32ada102055144a47dd45d542f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ed2098e95f737d158ebf84432d835c02bf816e5606db746500e68802d9b274b"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a3xUYB1X.length;i++)if(i%2==0)x.push(a3xUYB1X[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}