rule sig_20160527_3b3a1acbdc2fbccc4144fe57b3540bd8 {
  meta:
    description = "datamaliciousorder - file 20160527_3b3a1acbdc2fbccc4144fe57b3540bd8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78742cf72b14b3c018914866db7d26eeb98d1254035c3590de5aeab9444d0168"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a1zLqTN.length;i++)if(i%2==0)x.push(a1zLqTN[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}