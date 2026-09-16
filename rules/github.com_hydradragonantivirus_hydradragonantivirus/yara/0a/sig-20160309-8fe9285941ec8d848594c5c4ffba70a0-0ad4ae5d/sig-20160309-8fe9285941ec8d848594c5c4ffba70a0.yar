rule sig_20160309_8fe9285941ec8d848594c5c4ffba70a0 {
  meta:
    description = "datamaliciousorder - file 20160309_8fe9285941ec8d848594c5c4ffba70a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96f7d038611c634dfe2c8b8475b2f24cd47e6b556d3f159e3ca002a10ef788c9"

  strings:
    $s1  = "return RpFncEe[0] + RpFncEe[2] + RpFncEe[4] + \".F\" + RpFncEe[7] + RpFncEe[9] + RpFncEe[12] + RpFncEe[14];" fullword ascii
    $s2  = "var wL = true  , NhgA = khW[7] + khW[9] + khW[11];" fullword ascii
    $s3  = "zxlKc.open(YZHHJ,QlYPW,false);" fullword ascii
    $s4  = "var khW = (\"2.XMLHTTP kCVZVcW AozUA XML ream St jTbpJFdR AD XlFfCpN O CVxs D\").split(\" \");" fullword ascii
    $s5  = "var RpFncEe = \"Sc keScOAB r PVjARBwfo ipting EKqEeoZ vNN ile FnSjNsekdSMWGL System tM HKfWJ Obj oFxCye ect BMiolvL\".split(\" " ascii
    $s6  = "function MFLYIhJ(GndS,oKVML) {" fullword ascii
    $s7  = "function wrlxvDHa() {" fullword ascii
    $s8  = "if (m >= pKOzz.length) {break;}" fullword ascii
    $s9  = "function JvnhZeEaI(vBtOD,jcEro,vTXYW,nner) {" fullword ascii
    $s10 = "if (OSZNw == 1099-899){return true;} else {return false;}" fullword ascii
    $s11 = "return new ActiveXObject(bOFHcO);" fullword ascii
    $s12 = "return UkDrx.status;" fullword ascii
    $s13 = "return XrUDT;" fullword ascii
    $s14 = "function eDvc(hQNji) {" fullword ascii
    $s15 = "function atNk(OSZNw) {" fullword ascii
    $s16 = "if (Hdwqp > 174186-450){return true;} else {return false;}" fullword ascii
    $s17 = "return mSFRxdr" fullword ascii
    $s18 = "function gvSmwebb(pgc) {" fullword ascii
    $s19 = "function fkRn(pKOzz) {" fullword ascii
    $s20 = "function rQxE(ZejYY,LCGOl) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}