rule sig_20160321_7bf264b4a58ab13cb8bb800f56bc3a0d {
  meta:
    description = "datamaliciousorder - file 20160321_7bf264b4a58ab13cb8bb800f56bc3a0d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc30695205541b89f1b0cbd2cf8a3c643fc18afd2e3048a6fe6e51261d6a7644"

  strings:
    $s1  = "return WScript.CreateObject(tAoMO);" fullword ascii
    $s2  = "var Xx = true  , FPPT = HYE[7] + HYE[9] + HYE[11];" fullword ascii
    $s3  = "return SqmOnYP[0] + SqmOnYP[2] + SqmOnYP[4] + \".F\" + SqmOnYP[7] + SqmOnYP[9] + SqmOnYP[12] + SqmOnYP[14];" fullword ascii
    $s4  = "TacsC.open(oxegJ,UWHkF,false);" fullword ascii
    $s5  = "var SqmOnYP = XrJaW(QozpGyJGqA+\" \"+\"System Bf rWfHP Obj IOsXua ect kvTzErS HDDay\", \" \");" fullword ascii
    $s6  = "var HYE = (\"2.XMLHTTP PdIAhlF eRndR XML ream St ZlGXwegC AD CKekAOx O hVFm D\").split(\" \");" fullword ascii
    $s7  = "function rXGOgau(pbfa) {" fullword ascii
    $s8  = "function vhZI(JnRUx) {" fullword ascii
    $s9  = "if (DRWBR > 181746-254){return true;} else {return false;}" fullword ascii
    $s10 = "function kEEa(GeafF,dapzX) {" fullword ascii
    $s11 = "Xyb = t; break; " fullword ascii
    $s12 = "if (PezcJ == 427-227){return true;} else {return false;}" fullword ascii
    $s13 = "return new ActiveXObject(MOLHku);" fullword ascii
    $s14 = "function dRiYOows(LGq) {" fullword ascii
    $s15 = "function azAH(zCOxq) {" fullword ascii
    $s16 = "if (B >= srOHW.length) {break;}" fullword ascii
    $s17 = "function FIiMN(YxHWnx) {" fullword ascii
    $s18 = "return YxHWnx.position=629-629;" fullword ascii
    $s19 = "function kbYlOnJUR(UbFLM) {" fullword ascii
    $s20 = "if(t>=O.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}