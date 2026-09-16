rule sig_20160527_a0bab8bbc6905fb5491590d11619210d {
  meta:
    description = "datamaliciousorder - file 20160527_a0bab8bbc6905fb5491590d11619210d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ffa4539f31ba8f3559dd60b9a2a1f768ab92ef9830d8182a7dd0d4868a714757"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aSz3ZGht069.length;i++)if(i%2==0)x.push(aSz3ZGht069[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}