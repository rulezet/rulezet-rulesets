rule sig_20160527_825a2a082c6f749c24b39d16c801de13 {
  meta:
    description = "datamaliciousorder - file 20160527_825a2a082c6f749c24b39d16c801de13.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc1d486c508de2778117f0b35367ca14fcda11142d24c83e281603575cc64088"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aPIfFkMK.length;i++)if(i%2==0)x.push(aPIfFkMK[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}