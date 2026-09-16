rule sig_20160527_5f7f35b15166858f1064a928a56397c1 {
  meta:
    description = "datamaliciousorder - file 20160527_5f7f35b15166858f1064a928a56397c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "543b49b20ae5d7ad4f2b1441381465572abe27076fc0cc8ab94b1413c892b7ad"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aI0TdBdL8WG.length;i++)if(i%2==0)x.push(aI0TdBdL8WG[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}