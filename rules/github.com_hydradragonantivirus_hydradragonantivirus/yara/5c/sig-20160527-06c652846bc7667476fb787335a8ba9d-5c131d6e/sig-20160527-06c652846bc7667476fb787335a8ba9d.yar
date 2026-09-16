rule sig_20160527_06c652846bc7667476fb787335a8ba9d {
  meta:
    description = "datamaliciousorder - file 20160527_06c652846bc7667476fb787335a8ba9d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac0c1b497730ce16f93b5deeda08c05bf0554a5498507031aedbcb4568a983d0"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<am62g7.length;i++)if(i%2==0)x.push(am62g7[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}