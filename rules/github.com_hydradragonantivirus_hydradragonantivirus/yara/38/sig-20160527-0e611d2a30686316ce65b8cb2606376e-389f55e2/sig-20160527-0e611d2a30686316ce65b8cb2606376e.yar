rule sig_20160527_0e611d2a30686316ce65b8cb2606376e {
  meta:
    description = "datamaliciousorder - file 20160527_0e611d2a30686316ce65b8cb2606376e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a8dc9fa8be2b7a9e946e3c5e694ff157000e07cb57027c0b866291a1e886a2cb"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a5kvt4wY.length;i++)if(i%2==0)x.push(a5kvt4wY[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}