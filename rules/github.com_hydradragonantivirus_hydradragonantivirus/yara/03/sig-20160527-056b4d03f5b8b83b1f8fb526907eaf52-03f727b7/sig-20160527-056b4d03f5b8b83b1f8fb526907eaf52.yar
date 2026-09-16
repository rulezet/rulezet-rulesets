rule sig_20160527_056b4d03f5b8b83b1f8fb526907eaf52 {
  meta:
    description = "datamaliciousorder - file 20160527_056b4d03f5b8b83b1f8fb526907eaf52.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e49d9c674a0a5f157faa5e2f171ef4c5d165d42ed69ea51d9c9c6c6d3a2912c2"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a2GoylqQzzG.length;i++)if(i%2==0)x.push(a2GoylqQzzG[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}