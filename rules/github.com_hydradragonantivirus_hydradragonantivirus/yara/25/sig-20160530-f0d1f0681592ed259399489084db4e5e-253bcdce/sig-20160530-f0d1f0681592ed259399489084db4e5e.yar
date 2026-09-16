rule sig_20160530_f0d1f0681592ed259399489084db4e5e {
  meta:
    description = "datamaliciousorder - file 20160530_f0d1f0681592ed259399489084db4e5e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b33bcdcfa15fecdd8158b88186600e398cde210d355c74e65690b5c87bc0bfab"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aFRRCK5NnK.length;i++)if(i%2==0)x.push(aFRRCK5NnK[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}