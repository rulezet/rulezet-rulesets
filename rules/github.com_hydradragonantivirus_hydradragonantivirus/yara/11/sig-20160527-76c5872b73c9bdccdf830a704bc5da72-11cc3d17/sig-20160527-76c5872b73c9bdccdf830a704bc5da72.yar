rule sig_20160527_76c5872b73c9bdccdf830a704bc5da72 {
  meta:
    description = "datamaliciousorder - file 20160527_76c5872b73c9bdccdf830a704bc5da72.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21143da67553ba4f07b73d20450fdaea6ea5f9649170d9d6d8f60b7933472c76"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a9huXLgky.length;i++)if(i%2==0)x.push(a9huXLgky[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}