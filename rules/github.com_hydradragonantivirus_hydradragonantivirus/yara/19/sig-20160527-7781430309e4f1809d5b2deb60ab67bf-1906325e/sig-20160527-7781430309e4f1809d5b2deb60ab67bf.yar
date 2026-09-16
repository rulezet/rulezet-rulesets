rule sig_20160527_7781430309e4f1809d5b2deb60ab67bf {
  meta:
    description = "datamaliciousorder - file 20160527_7781430309e4f1809d5b2deb60ab67bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a146596549fde3de8e68b754c9875591fadd7f94dd69a0bf6dd7dbccfd46d8c"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a1pPGIDW.length;i++)if(i%2==0)x.push(a1pPGIDW[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}