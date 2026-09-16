rule sig_20160321_ed69a12d3153194756d593229e3b65d6 {
  meta:
    description = "datamaliciousorder - file 20160321_ed69a12d3153194756d593229e3b65d6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7981c5f7217a41cc364a0886ccd8c83f853c09fe45376d2fa39565eeb145c91"

  strings:
    $s1  = "return WScript.CreateObject(ejbBn);" fullword ascii
    $s2  = "function gpmt(NPSpY) {" fullword ascii
    $s3  = "if (NPSpY > 175390-863){return true;} else {return false;}" fullword ascii
    $s4  = "var fa = true  , jRAM = siV[7] + siV[9] + siV[11];" fullword ascii
    $s5  = "return EImsdrM[0] + EImsdrM[2] + EImsdrM[4] + \".F\" + EImsdrM[7] + EImsdrM[9] + EImsdrM[12] + EImsdrM[14];" fullword ascii
    $s6  = "var siV = (\"2.XMLHTTP RHxHJUd sVcyo XML ream St MTNnGNTZ AD wAxzVdO O synO D\").split(\" \");" fullword ascii
    $s7  = "var EImsdrM = rNlmW(NYnrZxRUmQ+\" \"+\"System Oe jYjUk Obj OAzbOr ect MwSaewE hSIxO\", \" \");" fullword ascii
    $s8  = "yczrW.open(BTaXe,WrmXQ,false);" fullword ascii
    $s9  = "return EaGoe.status;" fullword ascii
    $s10 = "return jhqO.ExpandEnvironmentStrings(LRIbK);" fullword ascii
    $s11 = "function JQXN(ejbBn) {" fullword ascii
    $s12 = "fVT = I; break; " fullword ascii
    $s13 = "return JjS.size;" fullword ascii
    $s14 = "return QUpQ[TXpRSj[0]];" fullword ascii
    $s15 = "function WmwKeTK(QUpQ) {" fullword ascii
    $s16 = "function NXuUNhkt(JjS) {" fullword ascii
    $s17 = "function rNlmW(YFK,dODWI) {" fullword ascii
    $s18 = "function AaXe(ufaPE) {" fullword ascii
    $s19 = "if (ufaPE == 539-339){return true;} else {return false;}" fullword ascii
    $s20 = "return JQQLtz.position=917-917;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}