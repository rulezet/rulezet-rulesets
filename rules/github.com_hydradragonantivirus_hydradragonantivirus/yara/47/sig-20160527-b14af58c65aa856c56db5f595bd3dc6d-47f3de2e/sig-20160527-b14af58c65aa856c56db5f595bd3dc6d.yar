rule sig_20160527_b14af58c65aa856c56db5f595bd3dc6d {
  meta:
    description = "datamaliciousorder - file 20160527_b14af58c65aa856c56db5f595bd3dc6d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80921099a22d9eb48a755ffd27c9749d9adbd30331a28318259831d2f6dfa39d"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aAAzqjbmr.length;i++)if(i%2==0)x.push(aAAzqjbmr[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}