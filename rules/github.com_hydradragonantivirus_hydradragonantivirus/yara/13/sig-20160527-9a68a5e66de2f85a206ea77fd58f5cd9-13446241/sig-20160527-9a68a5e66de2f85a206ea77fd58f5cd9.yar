rule sig_20160527_9a68a5e66de2f85a206ea77fd58f5cd9 {
  meta:
    description = "datamaliciousorder - file 20160527_9a68a5e66de2f85a206ea77fd58f5cd9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73f4053fc01b08525fab787a2977d153f73f840aa173bad63a232e9ea76b200d"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aGmHTey.length;i++)if(i%2==0)x.push(aGmHTey[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}