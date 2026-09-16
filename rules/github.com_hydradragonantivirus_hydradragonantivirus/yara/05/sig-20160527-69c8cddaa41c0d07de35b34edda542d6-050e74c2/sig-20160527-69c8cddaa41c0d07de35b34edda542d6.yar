rule sig_20160527_69c8cddaa41c0d07de35b34edda542d6 {
  meta:
    description = "datamaliciousorder - file 20160527_69c8cddaa41c0d07de35b34edda542d6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f6bd6bfc6c25600b4435c44fb61a115931ca962f43540fe8b867383799992638"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<ad83suV.length;i++)if(i%2==0)x.push(ad83suV[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}