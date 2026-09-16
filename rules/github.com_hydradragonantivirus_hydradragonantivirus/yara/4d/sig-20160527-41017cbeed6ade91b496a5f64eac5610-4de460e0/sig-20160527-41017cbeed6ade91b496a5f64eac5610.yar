rule sig_20160527_41017cbeed6ade91b496a5f64eac5610 {
  meta:
    description = "datamaliciousorder - file 20160527_41017cbeed6ade91b496a5f64eac5610.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b251765324987f4ab9da5b18c9cd58d3e759510dbcef45e4aa72f2c5a9cb6e9d"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aTYZUEqQQ1w.length;i++)if(i%2==0)x.push(aTYZUEqQQ1w[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}