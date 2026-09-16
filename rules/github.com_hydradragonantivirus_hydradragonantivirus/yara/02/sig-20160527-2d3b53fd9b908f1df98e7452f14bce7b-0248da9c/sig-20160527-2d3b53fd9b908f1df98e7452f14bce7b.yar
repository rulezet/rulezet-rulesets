rule sig_20160527_2d3b53fd9b908f1df98e7452f14bce7b {
  meta:
    description = "datamaliciousorder - file 20160527_2d3b53fd9b908f1df98e7452f14bce7b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6dd5cb081373f2cde76ef9d954c2fdea93b4e7314c60344bbae6a949e811dc81"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aqtok5mhJYB.length;i++)if(i%2==0)x.push(aqtok5mhJYB[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}