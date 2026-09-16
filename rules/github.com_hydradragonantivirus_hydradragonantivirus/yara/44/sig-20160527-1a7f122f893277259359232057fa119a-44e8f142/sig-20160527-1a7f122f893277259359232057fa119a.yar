rule sig_20160527_1a7f122f893277259359232057fa119a {
  meta:
    description = "datamaliciousorder - file 20160527_1a7f122f893277259359232057fa119a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6809047796f57b1b41421f12053d40e6a9d1cbc6213b7a15bad5779cff9a59c4"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aPKqQEdDaGV.length;i++)if(i%2==0)x.push(aPKqQEdDaGV[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}