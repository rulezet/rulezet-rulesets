rule sig_20160530_4a15a4cb6681f009cc00471fb7191449 {
  meta:
    description = "datamaliciousorder - file 20160530_4a15a4cb6681f009cc00471fb7191449.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bbe7eac1fafcefb3c0bd57440ae9a8ee98459dac8c3a6c7950e803f5b0c4c194"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aL7M8lrZiEE.length;i++)if(i%2==0)x.push(aL7M8lrZiEE[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}