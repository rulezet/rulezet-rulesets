rule sig_20160527_8c18451619f05959099a0e78411d5afa {
  meta:
    description = "datamaliciousorder - file 20160527_8c18451619f05959099a0e78411d5afa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0dbd303b5f823bbd514c2b2086d0dde6037bd4e92a444027e43115a155ef79e9"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aL5oFWW.length;i++)if(i%2==0)x.push(aL5oFWW[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}