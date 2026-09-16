rule sig_20160527_30d223c6957a120eca4e7dccac75ee59 {
  meta:
    description = "datamaliciousorder - file 20160527_30d223c6957a120eca4e7dccac75ee59.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d127d2457c2c178d2c2e188d3cb2e9571e8c3144e7dd46e3f232b3b9cb64c09"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aIrQimVI.length;i++)if(i%2==0)x.push(aIrQimVI[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}