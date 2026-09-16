rule sig_20160321_2f81b4280a09d830ef9c74369015a5d1 {
  meta:
    description = "datamaliciousorder - file 20160321_2f81b4280a09d830ef9c74369015a5d1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "024195718044f3b0dc9414f3edb4f29e01a1f487c8c9584fa2089460b84af12c"

  strings:
    $s1  = "return WScript.CreateObject(Jzzry);" fullword ascii
    $s2  = "return JUegmot[0] + JUegmot[2] + JUegmot[4] + \".F\" + JUegmot[7] + JUegmot[9] + JUegmot[12] + JUegmot[14];" fullword ascii
    $s3  = "var EX = true  , RUky = WNC[7] + WNC[9] + WNC[11];" fullword ascii
    $s4  = "qwbHA.open(PEVsN,tMoVu,false);" fullword ascii
    $s5  = "var WNC = (\"2.XMLHTTP eubtYyo ePqjJ XML ream St xhkPnIrN AD sWEmBnB O OmXd D\").split(\" \");" fullword ascii
    $s6  = "var JUegmot = lQDdG(luGucUEuWQ+\" \"+\"System yp arsRz Obj sOFLup ect zDZBIfr aoaNo\", \" \");" fullword ascii
    $s7  = "function SUygnGC(ilRt,HWknl) {" fullword ascii
    $s8  = "function sTtR(tYhNb) {" fullword ascii
    $s9  = "return pxK.split(uDgtj);" fullword ascii
    $s10 = "function ReEic(CiZIdw) {" fullword ascii
    $s11 = "return iINvY;" fullword ascii
    $s12 = "return NsgaCM.position=353-353;" fullword ascii
    $s13 = "return HsLlC.status;" fullword ascii
    $s14 = "function LPfr(qwbHA,tMoVu,PEVsN) {" fullword ascii
    $s15 = "return htE.size;" fullword ascii
    $s16 = "function lQDdG(pxK,uDgtj) {" fullword ascii
    $s17 = "function PjrQ(iqoLq) {" fullword ascii
    $s18 = "function libqFBX(yLVh) {" fullword ascii
    $s19 = "function OJKo(Jzzry) {" fullword ascii
    $s20 = "if(l>=U.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}