rule sig_20160527_c83487720e4cee8c1c866ee0404e711b {
  meta:
    description = "datamaliciousorder - file 20160527_c83487720e4cee8c1c866ee0404e711b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33b454a804fa587bfc3c65d88523bc86835ef1ab06b2696e18f743ab18723a7b"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aSRc4e.length;i++)if(i%2==0)x.push(aSRc4e[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}