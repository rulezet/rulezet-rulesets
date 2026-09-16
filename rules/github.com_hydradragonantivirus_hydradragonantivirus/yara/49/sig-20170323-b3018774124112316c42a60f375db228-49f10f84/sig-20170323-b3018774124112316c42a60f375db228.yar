rule sig_20170323_b3018774124112316c42a60f375db228 {
  meta:
    description = "datamaliciousorder - file 20170323_b3018774124112316c42a60f375db228.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3d179e2b0b5c4db960fd1174d4691c27a5d5d81ff217f8121ce9d5a337477e9"

  strings:
    $s1  = "return Math.floor(Math.random() * rssgteleyk)" fullword ascii
    $s2  = "function pqgueykbcn()" fullword ascii
    $s3  = "return wtjltjhpod[zhlutpmfxb(wtjltjhpod)];" fullword ascii
    $s4  = "return parseInt(xroixsqvpg,16);" fullword ascii
    $s5  = "return ugjqmbtlva;" fullword ascii
    $s6  = "function zhlutpmfxb(fijxmupsmi)" fullword ascii
    $s7  = "ugjqmbtlva=(new Function(\"nrufaolwyf\",\"var xutbocrotz=new Array(167,27,25,49,106,184,153,32,11,62,73,46,15,15,238),mkivkwkpla" ascii
    $s8  = "return yijicuquwl;" fullword ascii
    $s9  = "function jweekumphb(gfummmwtrc)" fullword ascii
    $s10 = "function fyjceivxjh(x)" fullword ascii
    $s11 = "ugjqmbtlva=(new Function(\"nrufaolwyf\",\"var xutbocrotz=new Array(167,27,25,49,106,184,153,32,11,62,73,46,15,15,238),mkivkwkpla" ascii
    $s12 = "function bpsslwyrxx(xroixsqvpg)" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}