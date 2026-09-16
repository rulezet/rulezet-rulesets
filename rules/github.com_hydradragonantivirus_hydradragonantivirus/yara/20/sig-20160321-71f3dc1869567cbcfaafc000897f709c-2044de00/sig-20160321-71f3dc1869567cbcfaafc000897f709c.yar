rule sig_20160321_71f3dc1869567cbcfaafc000897f709c {
  meta:
    description = "datamaliciousorder - file 20160321_71f3dc1869567cbcfaafc000897f709c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ea791069ff3c16717d1ced6fc86330e322d56ed7473f0cdea116861b229b044"

  strings:
    $s1  = "return WScript.CreateObject(nSPuS);" fullword ascii
    $s2  = "return XAHUzma[0] + XAHUzma[2] + XAHUzma[4] + \".F\" + XAHUzma[7] + XAHUzma[9] + XAHUzma[12] + XAHUzma[14];" fullword ascii
    $s3  = "var Qq = true  , TDiv = jHu[7] + jHu[9] + jHu[11];" fullword ascii
    $s4  = "var jHu = (\"2.XMLHTTP Ktroygf TGegn XML ream St WNrvdUtT AD lZbZYMC O IUtY D\").split(\" \");" fullword ascii
    $s5  = "Dpake.open(qFMzG,WYEwM,false);" fullword ascii
    $s6  = "var XAHUzma = DtebR(fGfGvEkrxI+\" \"+\"System Fn UzQpH Obj ZbPLWV ect eIGxVKt ozrXB\", \" \");" fullword ascii
    $s7  = "function jmwc(jPIho,ZZEEo) {" fullword ascii
    $s8  = "return new ActiveXObject(DpwczQ);" fullword ascii
    $s9  = "function rChK(nSPuS) {" fullword ascii
    $s10 = "if (btWPk == 802-602){return true;} else {return false;}" fullword ascii
    $s11 = "function esatuimM(hEBE) {" fullword ascii
    $s12 = "return sOoe.ExpandEnvironmentStrings(tUboK);" fullword ascii
    $s13 = "function XKFv(egnoK) {" fullword ascii
    $s14 = "return lgs.split(MjhIB);" fullword ascii
    $s15 = "function aoElGbKvK(lMFmt) {" fullword ascii
    $s16 = "function LUuC(wtibZ) {" fullword ascii
    $s17 = "return JUZ.size;" fullword ascii
    $s18 = "function LefeBpA(sOoe,tUboK) {" fullword ascii
    $s19 = "function DtebR(lgs,MjhIB) {" fullword ascii
    $s20 = "if(n>=t.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}