rule sig_20160527_39884019d68a38a84699ca6ba37e157a {
  meta:
    description = "datamaliciousorder - file 20160527_39884019d68a38a84699ca6ba37e157a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07db1caca67e05610a0ea47819e1a978f2460aa5bc5a333b57e855fd200cd50f"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aSUrdYEFWG.length;i++)if(i%2==0)x.push(aSUrdYEFWG[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}