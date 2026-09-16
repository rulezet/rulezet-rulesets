rule sig_20160527_0c5a577352447af7981b3916aa3cdaa3 {
  meta:
    description = "datamaliciousorder - file 20160527_0c5a577352447af7981b3916aa3cdaa3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18beb5d0bcef5d3a9d5ae3a3efe9d8f397643287852f79a8d8e552dcfd7fc8ef"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<annKpaEXxE8.length;i++)if(i%2==0)x.push(annKpaEXxE8[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}