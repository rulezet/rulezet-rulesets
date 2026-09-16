rule sig_20160527_5f58816e877bbcf3d26b9e57ddf06857 {
  meta:
    description = "datamaliciousorder - file 20160527_5f58816e877bbcf3d26b9e57ddf06857.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8446bffa2918d341f3b1a8a8be518e6a3c626b025b9857298f17a58b0be5779"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aSKlTIHFOVk.length;i++)if(i%2==0)x.push(aSKlTIHFOVk[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}