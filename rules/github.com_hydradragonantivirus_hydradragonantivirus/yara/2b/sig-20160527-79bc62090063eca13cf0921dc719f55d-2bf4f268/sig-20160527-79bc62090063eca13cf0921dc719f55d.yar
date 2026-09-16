rule sig_20160527_79bc62090063eca13cf0921dc719f55d {
  meta:
    description = "datamaliciousorder - file 20160527_79bc62090063eca13cf0921dc719f55d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0afb50301ee4ad8865d0c0a11b6c5b3d6f80f83653999eb4d61674e065ddaf92"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a4Akh6liBL.length;i++)if(i%2==0)x.push(a4Akh6liBL[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}