rule sig_20160527_661658b0f39128d5c38ef448b2553d73 {
  meta:
    description = "datamaliciousorder - file 20160527_661658b0f39128d5c38ef448b2553d73.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff8782d90ea8d4797a1da974456659254c917f37b7ececc3c56b96d201866856"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a7zvDsmXc.length;i++)if(i%2==0)x.push(a7zvDsmXc[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}