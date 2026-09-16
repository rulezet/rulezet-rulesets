rule sig_20160527_1755902a29bcf5dcefb4b07ca3bddce7 {
  meta:
    description = "datamaliciousorder - file 20160527_1755902a29bcf5dcefb4b07ca3bddce7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c554eeda92b8f152802904228771d83d92a1c5f6213e185558602b6fdc2d3ed6"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<apRNEp.length;i++)if(i%2==0)x.push(apRNEp[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}