rule sig_20160308_37681a7c5c6e010f1343d2353d2340ee {
  meta:
    description = "datamaliciousorder - file 20160308_37681a7c5c6e010f1343d2353d2340ee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8581d7417613b92dc830ccf4616722d914f5671bf6bd743e0675c70f000f8956"

  strings:
    $s1  = "return ufAuwRi[0] + ufAuwRi[2] + ufAuwRi[4] + \".F\" + ufAuwRi[7] + ufAuwRi[9] + ufAuwRi[12] + ufAuwRi[14];" fullword ascii
    $s2  = "var IG = true  , YeQW = dzb[7] + dzb[9] + dzb[11];" fullword ascii
    $s3  = "QNZcd.open(eFisi,wEvGy,false);" fullword ascii
    $s4  = "var dzb = (\"2.XMLHTTP PaIFiAD drZDe XML ream St OEuWZSAh AD NNsRktA O Bqnu D\").split(\" \");" fullword ascii
    $s5  = "var ufAuwRi = \"Sc glDdKts r eEkeLYXGW ipting LzMhmbQ ssq ile LAiDMfBBTdESHN System Da BGvoj Obj RDKEEv ect JwILkCD\".split(\" " ascii
    $s6  = "function fkqT(zsjke) {" fullword ascii
    $s7  = "if (ecKfo == 595-395){return true;} else {return false;}" fullword ascii
    $s8  = "if (lsOeG > 155002-868){return true;} else {return false;}" fullword ascii
    $s9  = "function bCfW(ecKfo) {" fullword ascii
    $s10 = "return LcMkq.status;" fullword ascii
    $s11 = "if(U>=C.length) {break;}" fullword ascii
    $s12 = "function CYps(LByDQ) {" fullword ascii
    $s13 = "function EsKF(QNZcd,wEvGy,eFisi) {" fullword ascii
    $s14 = "if (l >= LByDQ.length) {break;}" fullword ascii
    $s15 = "return mRp.size;" fullword ascii
    $s16 = "return tY.ExpandEnvironmentStrings(CUbLW[6]+CUbLW[7]+CUbLW[8]);" fullword ascii
    $s17 = "function crBE(VFtJX) {" fullword ascii
    $s18 = "return XXtGk;" fullword ascii
    $s19 = "function LItTyLpcz(jcPIXmepjiZ) {" fullword ascii
    $s20 = "function sKhE(HMIcG) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}