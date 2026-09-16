rule sig_20160314_898cb8acd687fd9981733bea810d9113 {
  meta:
    description = "datamaliciousorder - file 20160314_898cb8acd687fd9981733bea810d9113.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b41c34fbb1fd01f4707a64dcdf5940285fdd95ae669354acb6fb467ba6c0a23e"

  strings:
    $s1  = "return TyoGpPZ[0] + TyoGpPZ[2] + TyoGpPZ[4] + \".F\" + TyoGpPZ[7] + TyoGpPZ[9] + TyoGpPZ[12] + TyoGpPZ[14];" fullword ascii
    $s2  = "var BN = true  , kTlg = SBh[7] + SBh[9] + SBh[11];" fullword ascii
    $s3  = "var SBh = (\"2.XMLHTTP KqVbajG qPbRc XML ream St IXpumkvk AD ndhtjoJ O arEe D\").split(\" \");" fullword ascii
    $s4  = "var TyoGpPZ = \"Sc xUfzkZM r dZZVeekVA ipting qxYhECy Lmx ile gVFJtTUKNHZWIJ System Xc Yjcds Obj wnmqDD ect XcptMjS yGkGv\".spli" ascii
    $s5  = "xgvbW.open(NgaCw,RjyUQ,false);" fullword ascii
    $s6  = "var TyoGpPZ = \"Sc xUfzkZM r dZZVeekVA ipting qxYhECy Lmx ile gVFJtTUKNHZWIJ System Xc Yjcds Obj wnmqDD ect XcptMjS yGkGv\".spli" ascii
    $s7  = "if(f>=Q.length) {break;}" fullword ascii
    $s8  = "return oqiU.responseBody;" fullword ascii
    $s9  = "function jOAngLA(JePt,WvVcR) {" fullword ascii
    $s10 = "function PkYS(BCYPa) {" fullword ascii
    $s11 = "function UtNaJQaZO() {" fullword ascii
    $s12 = "function tnmi(jWhby) {" fullword ascii
    $s13 = "if (l >= hSDYt.length) {break;}" fullword ascii
    $s14 = "function mnCeyoOIM(zmwSrOLInwZ) {" fullword ascii
    $s15 = "function HMAL(SMckf,dxgsj) {" fullword ascii
    $s16 = "function NIdotsNU(QrT) {" fullword ascii
    $s17 = "return new ActiveXObject(bltUys);" fullword ascii
    $s18 = "if (jWhby > 191838-807){return true;} else {return false;}" fullword ascii
    $s19 = "Cu = 1;HrcMn(dBr);coKe(dBr,/*TRKT80nM8k*/BnaT/*Mlel96NIky*/+dtkENlx+UWU[882-875]+UWU[845-836]+UWU[671-660]); try  {" fullword ascii
    $s20 = "function Gprt(xgvbW,RjyUQ,NgaCw) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}