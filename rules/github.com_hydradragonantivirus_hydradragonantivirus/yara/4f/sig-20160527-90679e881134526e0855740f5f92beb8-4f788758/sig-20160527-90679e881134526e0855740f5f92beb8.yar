rule sig_20160527_90679e881134526e0855740f5f92beb8 {
  meta:
    description = "datamaliciousorder - file 20160527_90679e881134526e0855740f5f92beb8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d93f9b06f22afeda75da2a707ca58a29e71e353365994d1dc6d38223252eba6d"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aCScPcuQVGO.length;i++)if(i%2==0)x.push(aCScPcuQVGO[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}