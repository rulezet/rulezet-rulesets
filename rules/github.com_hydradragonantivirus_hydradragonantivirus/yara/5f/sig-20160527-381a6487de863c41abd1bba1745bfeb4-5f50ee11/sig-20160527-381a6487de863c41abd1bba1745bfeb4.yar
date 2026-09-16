rule sig_20160527_381a6487de863c41abd1bba1745bfeb4 {
  meta:
    description = "datamaliciousorder - file 20160527_381a6487de863c41abd1bba1745bfeb4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "927412fdd9c48962e671b42f9aed7f435c69a3e42544ac22a6ffde2814c8718d"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aSfE3gJN.length;i++)if(i%2==0)x.push(aSfE3gJN[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}