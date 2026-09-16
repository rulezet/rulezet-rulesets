rule sig_20160527_cd6d4ae23d73b28bb1cdb406f8afd2ce {
  meta:
    description = "datamaliciousorder - file 20160527_cd6d4ae23d73b28bb1cdb406f8afd2ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "064d881d5ab992050da3bee882c79af70c4f7c75f1609774eaa9064815f92f16"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<auuHqd.length;i++)if(i%2==0)x.push(auuHqd[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}