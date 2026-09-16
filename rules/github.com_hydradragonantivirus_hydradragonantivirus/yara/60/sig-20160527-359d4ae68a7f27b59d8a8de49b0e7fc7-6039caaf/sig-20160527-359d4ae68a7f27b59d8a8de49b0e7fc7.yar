rule sig_20160527_359d4ae68a7f27b59d8a8de49b0e7fc7 {
  meta:
    description = "datamaliciousorder - file 20160527_359d4ae68a7f27b59d8a8de49b0e7fc7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c46d44b3293a67b237b4a7c5a26b07971f70dd5de9573aa628f9630326a1eef"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aRP0gu.length;i++)if(i%2==0)x.push(aRP0gu[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}