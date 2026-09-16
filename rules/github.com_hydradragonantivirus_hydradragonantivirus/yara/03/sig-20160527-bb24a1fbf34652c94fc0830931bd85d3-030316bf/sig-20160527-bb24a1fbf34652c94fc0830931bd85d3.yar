rule sig_20160527_bb24a1fbf34652c94fc0830931bd85d3 {
  meta:
    description = "datamaliciousorder - file 20160527_bb24a1fbf34652c94fc0830931bd85d3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eee450815dbf735c91539e26f29211bb5d184ab83f78c03e432cad4d221627f7"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aVWZc52qMJA.length;i++)if(i%2==0)x.push(aVWZc52qMJA[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}