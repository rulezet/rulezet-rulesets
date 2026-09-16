rule sig_20160527_d6cc384620993492244cbb66371b7449 {
  meta:
    description = "datamaliciousorder - file 20160527_d6cc384620993492244cbb66371b7449.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6fa3566d350882e69db8f7125754abfa019d2b8d580d3061c54095d2eaa9f96b"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aQeeqRFoGJ.length;i++)if(i%2==0)x.push(aQeeqRFoGJ[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}