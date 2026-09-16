rule sig_20160405_8369823feed4c839229771b6cc66f331 {
  meta:
    description = "datamaliciousorder - file 20160405_8369823feed4c839229771b6cc66f331.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c5dba0ebec3ad23237328032dc1d008427d0519df4754be63dd5501e7c7df7f"

  strings:
    $s1  = "var vL = true  , YeOt = Byd[7] + Byd[9] + Byd[11];" fullword ascii
    $s2  = "return vZFaSyW[0] + vZFaSyW[2] + vZFaSyW[4] + \".F\" + vZFaSyW[7] + vZFaSyW[9] + vZFaSyW[12] + vZFaSyW[14];" fullword ascii
    $s3  = "bdgW.open(Qygkw,wSqOx,false);" fullword ascii
    $s4  = "var Byd = (\"2.XMLHTTP aabgYKz vGayK XML ream St dBTUBmwj AD CWcEOVt O Rbgc D\").split(\" \");" fullword ascii
    $s5  = "function zFSMqUD(WIxX,PSsiF) {" fullword ascii
    $s6  = "function PVVa(xBQSW) {" fullword ascii
    $s7  = "function yVVhTJ(YuhA,nKZFgR) {" fullword ascii
    $s8  = "return \"MkdIYALyUOPUVN\";" fullword ascii
    $s9  = "if (xBQSW == 906-706){return true;} else {return false;}" fullword ascii
    $s10 = "var dxfveBx = \"HSiQFo*vjr*pt.S\"+\"hell*SBPMyBx*Scri*\";" fullword ascii
    $s11 = "return qmiI[LiokGh[0]];" fullword ascii
    $s12 = "if(T>=U.length) {break;}" fullword ascii
    $s13 = "function wUYHPKEE(aPW) {" fullword ascii
    $s14 = "return OCdYNEQ;" fullword ascii
    $s15 = "function nGFgCII(qmiI) {" fullword ascii
    $s16 = "function EQGF(jCNJv) {" fullword ascii
    $s17 = "function lbjxuYJNG(VIytH) {" fullword ascii
    $s18 = "if (SqwFQ > 181448-203){return true;} else {return false;}" fullword ascii
    $s19 = "function kecl(oGeHb,wSqOx,Qygkw) {" fullword ascii
    $s20 = "return ijGj;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}