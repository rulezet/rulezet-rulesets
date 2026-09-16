rule sig_20160530_0e50917fd2f340d5d9e4a365a8009126 {
  meta:
    description = "datamaliciousorder - file 20160530_0e50917fd2f340d5d9e4a365a8009126.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad77e57d18cef0dca6537956687dbe7a2d170e82c1900dc0fe961293b9515856"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aQvmGM.length;i++)if(i%2==0)x.push(aQvmGM[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}