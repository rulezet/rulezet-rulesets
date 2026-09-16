rule sig_20160527_6a4849db179417c15887b7e734ce8b65 {
  meta:
    description = "datamaliciousorder - file 20160527_6a4849db179417c15887b7e734ce8b65.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b8659c89822666dcfe57a7c7e0c49baaf8cd4429f9d9fd8332470bbffa92e88"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aW5rBtmqT.length;i++)if(i%2==0)x.push(aW5rBtmqT[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}