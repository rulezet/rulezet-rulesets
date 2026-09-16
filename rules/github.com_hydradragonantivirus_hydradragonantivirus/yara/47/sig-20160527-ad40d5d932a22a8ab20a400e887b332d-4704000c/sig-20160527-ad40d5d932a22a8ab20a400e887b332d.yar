rule sig_20160527_ad40d5d932a22a8ab20a400e887b332d {
  meta:
    description = "datamaliciousorder - file 20160527_ad40d5d932a22a8ab20a400e887b332d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "882b229c4698aadaae4bee0d7ad167f2f3fe4402dbd9dbf1fdd0f575718cbfb4"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aUslqTmex.length;i++)if(i%2==0)x.push(aUslqTmex[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}