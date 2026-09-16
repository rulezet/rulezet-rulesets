rule sig_20160527_9daf9f1bb45bc714a235a69194585a2d {
  meta:
    description = "datamaliciousorder - file 20160527_9daf9f1bb45bc714a235a69194585a2d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f8527acceb63940b7ad64543f446c6d4bd342fd4a342fc53ba6905f572f7ea92"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<avNV5YTV.length;i++)if(i%2==0)x.push(avNV5YTV[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}