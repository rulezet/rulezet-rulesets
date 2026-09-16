rule sig_20170321_d2bdd39119af20dbfc0c1822224b59ba {
  meta:
    description = "datamaliciousorder - file 20170321_d2bdd39119af20dbfc0c1822224b59ba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21a5a0e752839fe59c9be63729976083d5ae4225f0e1f4db2ee51094be01e82a"

  strings:
    $s1  = "return yosciuktxy;" fullword ascii
    $s2  = "function kleoonfkcw()" fullword ascii
    $s3  = "function rimdmklpss()" fullword ascii
    $s4  = "function rjeboavvad(etqqfjtqvd)" fullword ascii
    $s5  = "return zijyrnscru[Math.floor(Math.random()*zijyrnscru.length)];" fullword ascii
    $s6  = "yosciuktxy=(new Function(\"kchxtbzlhg\",\"var ntqqwosnyv=new Array(244,93,89,248,108,41,130,197,219,125,106,21,95,230,230,35,204" ascii
    $s7  = "function zfnphrduis(guqevynald)" fullword ascii
    $s8  = "yosciuktxy=(new Function(\"kchxtbzlhg\",\"var ntqqwosnyv=new Array(244,93,89,248,108,41,130,197,219,125,106,21,95,230,230,35,204" ascii
    $s9  = "return parseInt(guqevynald,16);" fullword ascii
    $s10 = "return ocanonmwrt;" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}