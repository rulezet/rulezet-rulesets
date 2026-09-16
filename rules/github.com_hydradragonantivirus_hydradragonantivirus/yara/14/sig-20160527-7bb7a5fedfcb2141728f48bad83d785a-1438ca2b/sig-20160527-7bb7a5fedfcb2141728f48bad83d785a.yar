rule sig_20160527_7bb7a5fedfcb2141728f48bad83d785a {
  meta:
    description = "datamaliciousorder - file 20160527_7bb7a5fedfcb2141728f48bad83d785a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2a4827fcb5d014efa8308a2d53a26ae944849fb99149525658427df851b227d"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a1xXieLq3xI.length;i++)if(i%2==0)x.push(a1xXieLq3xI[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}