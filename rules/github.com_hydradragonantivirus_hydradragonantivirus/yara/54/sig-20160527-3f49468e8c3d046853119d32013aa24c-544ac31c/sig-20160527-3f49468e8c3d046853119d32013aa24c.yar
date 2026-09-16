rule sig_20160527_3f49468e8c3d046853119d32013aa24c {
  meta:
    description = "datamaliciousorder - file 20160527_3f49468e8c3d046853119d32013aa24c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "508515d1dc4e2cafa6cfeeee48917c4d70dd557c3ffb6274589b3a8cf0f0f7c2"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aX3IkP.length;i++)if(i%2==0)x.push(aX3IkP[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}