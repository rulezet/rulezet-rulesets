rule sig_20160527_e8273dec270e26330a8b4f6f633c7dc3 {
  meta:
    description = "datamaliciousorder - file 20160527_e8273dec270e26330a8b4f6f633c7dc3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02a69f891e29db6a8d9b47d94a03b6f59e14e1c6d9703a1c25462fb6ee0ca746"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aXQwIN.length;i++)if(i%2==0)x.push(aXQwIN[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}