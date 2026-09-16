rule sig_20160324_9292b3ca621d56a7e17c7780f3204dc8 {
  meta:
    description = "datamaliciousorder - file 20160324_9292b3ca621d56a7e17c7780f3204dc8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5493c3960f315ab7e7e37e383259498e956bb4562840766aa7f897b41e2a5cb4"

  strings:
    $s1  = "return WScript.CreateObject(sKLxj);" fullword ascii
    $s2  = "return ldHwAIO[0] + ldHwAIO[2] + ldHwAIO[4] + \".F\" + ldHwAIO[7] + ldHwAIO[9] + ldHwAIO[12] + ldHwAIO[14];" fullword ascii
    $s3  = "var NST = (\"2.XMLHTTP SZJrtbc IyGGg XML ream St EsbselQE AD RkLIDNM O Ctrj D\").split(\" \");" fullword ascii
    $s4  = "var ldHwAIO = XvKip(ahVsyrSnYe+\" \"+\"System Ge OhYzh Obj zacXmt ect FLlelJO pjeIU\", \" \");" fullword ascii
    $s5  = "gGkb.open(AMGMZ,qNJfR,false);" fullword ascii
    $s6  = "if(M>=S.length) {break;}" fullword ascii
    $s7  = "function XvKip(uUL,RzHjX) {" fullword ascii
    $s8  = "function QyAa(pMsKm) {" fullword ascii
    $s9  = "function TRtag(TCHWTv) {" fullword ascii
    $s10 = "return uUL.split(RzHjX);" fullword ascii
    $s11 = "if (npHRu > 155733-543){return true;} else {return false;}" fullword ascii
    $s12 = "if (TlDOx == 518-318){return true;} else {return false;}" fullword ascii
    $s13 = "var qAyYPnY = \"uzLRmf*dsM*pt.S\"+\"hell*nipZZea*Scri*\";" fullword ascii
    $s14 = "function uEkz(vgzRy,ToxzV) {" fullword ascii
    $s15 = "function UoSr(EXeMa) {" fullword ascii
    $s16 = "return WWTBZcO(mu,ZwzuZ[845-839]+ZwzuZ[736-729]+ZwzuZ[773-765]);" fullword ascii
    $s17 = "return pMsKm.status;" fullword ascii
    $s18 = "function mJrx(sKLxj) {" fullword ascii
    $s19 = "function XqkvhAznu(FVhuX) {" fullword ascii
    $s20 = "return new ActiveXObject(IRAP);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}