rule sig_20160527_8bd22c8c0f0155afe003e08863cbaf2c {
  meta:
    description = "datamaliciousorder - file 20160527_8bd22c8c0f0155afe003e08863cbaf2c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9767fa968c631c49225dc685bff886f8c439f26c9b571501d0012da2986ce891"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<atQySyOUy.length;i++)if(i%2==0)x.push(atQySyOUy[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}