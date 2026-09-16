rule sig_20160527_ed330c55b36dee037b4fa84a951dad94 {
  meta:
    description = "datamaliciousorder - file 20160527_ed330c55b36dee037b4fa84a951dad94.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3cdf6c8f846029845d568d95adaef2c8ca4aa9b533e687e0fb70da0d0e8aaae6"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aU2grK9B.length;i++)if(i%2==0)x.push(aU2grK9B[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}