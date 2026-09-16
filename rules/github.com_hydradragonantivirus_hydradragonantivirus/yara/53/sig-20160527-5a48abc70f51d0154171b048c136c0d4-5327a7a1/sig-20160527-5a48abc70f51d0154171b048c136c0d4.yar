rule sig_20160527_5a48abc70f51d0154171b048c136c0d4 {
  meta:
    description = "datamaliciousorder - file 20160527_5a48abc70f51d0154171b048c136c0d4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b1e92a9a4cd93e6e4464a713b73d5ebd344c6ce43639ee241040d9a1348eef2"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<ak8CRTVY.length;i++)if(i%2==0)x.push(ak8CRTVY[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}