rule sig_20160527_def232942d9e7a3c7a969c0f434da75e {
  meta:
    description = "datamaliciousorder - file 20160527_def232942d9e7a3c7a969c0f434da75e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13e156b1853fc146e14227d5e8ac36505f2bbd27d971954dbab9c0df83019846"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<abxECdUWq.length;i++)if(i%2==0)x.push(abxECdUWq[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}