rule sig_20160527_54b6358f67fdce33530478b4f873c0a3 {
  meta:
    description = "datamaliciousorder - file 20160527_54b6358f67fdce33530478b4f873c0a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bebaa1498aa98bf1633207460817e53e84ca0773b131d3ef210ad23d4eb0d6e9"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aCNccdN.length;i++)if(i%2==0)x.push(aCNccdN[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}