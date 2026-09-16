rule sig_20160323_9a7b7c2f8036a54d10780685f358cf1a {
  meta:
    description = "datamaliciousorder - file 20160323_9a7b7c2f8036a54d10780685f358cf1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c94db37d716a8398d2e4baa8ed84b03c72a9fc453be014c71a34eabb2d006ae"

  strings:
    $s1  = "return WScript.CreateObject(vqUJZ);" fullword ascii
    $s2  = "var RL = true  , JJqZ = rwt[7] + rwt[9] + rwt[11];" fullword ascii
    $s3  = "return kefCXtY[0] + kefCXtY[2] + kefCXtY[4] + \".F\" + kefCXtY[7] + kefCXtY[9] + kefCXtY[12] + kefCXtY[14];" fullword ascii
    $s4  = "var rwt = (\"2.XMLHTTP wafkRFv KdIkR XML ream St nbKSiNJG AD rTRQVlT O yXII D\").split(\" \");" fullword ascii
    $s5  = "function tMpN(pJLcZ,cFkMn) {" fullword ascii
    $s6  = "jwhn.open(xGTHJ,aqkDo,false);" fullword ascii
    $s7  = "var kefCXtY = MfOVd(LcYRYZilum+\" \"+\"System mX LJUPn Obj jBLtsc ect ciWLzVs CkVhD\", \" \");" fullword ascii
    $s8  = "if(m>=j.length) {break;}" fullword ascii
    $s9  = "function MfOVd(dBO,Vmxwp) {" fullword ascii
    $s10 = "function XPJk(ibRuE,HweXT) {" fullword ascii
    $s11 = "return dBO.split(Vmxwp);" fullword ascii
    $s12 = "return ZjhpDv.position=719-719;" fullword ascii
    $s13 = "return zxhkC;" fullword ascii
    $s14 = "function GfFZBkcz(Qmk) {" fullword ascii
    $s15 = "function oIsw(fZxFA) {" fullword ascii
    $s16 = "function bZUe(fDikd) {" fullword ascii
    $s17 = "function khZC(JRrHO) {" fullword ascii
    $s18 = "return Qmk.size;" fullword ascii
    $s19 = "function GwFeOzeGU(UpWMfHEYjYm) {" fullword ascii
    $s20 = "if (fZxFA > 174902-706){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}