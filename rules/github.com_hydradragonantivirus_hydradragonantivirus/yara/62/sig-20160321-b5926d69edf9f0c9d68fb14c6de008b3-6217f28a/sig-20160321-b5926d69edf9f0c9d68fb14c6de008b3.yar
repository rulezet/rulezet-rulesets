rule sig_20160321_b5926d69edf9f0c9d68fb14c6de008b3 {
  meta:
    description = "datamaliciousorder - file 20160321_b5926d69edf9f0c9d68fb14c6de008b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "772d8a58255a6659381fcea4c7407e5bc770284cd10223ddf773298e949acdef"

  strings:
    $s1  = "return WScript.CreateObject(VOJSb);" fullword ascii
    $s2  = "return ZKVUbTp[0] + ZKVUbTp[2] + ZKVUbTp[4] + \".F\" + ZKVUbTp[7] + ZKVUbTp[9] + ZKVUbTp[12] + ZKVUbTp[14];" fullword ascii
    $s3  = "var AJ = true  , qRxm = Qwy[7] + Qwy[9] + Qwy[11];" fullword ascii
    $s4  = "var Qwy = (\"2.XMLHTTP YwXrFjc VFnVm XML ream St nhuyHDTW AD KrKhZmP O RWiZ D\").split(\" \");" fullword ascii
    $s5  = "var ZKVUbTp = YcYED(vKhGlNxVNB+\" \"+\"System yy UswyT Obj sAPWzD ect HqErxnU dhUbn\", \" \");" fullword ascii
    $s6  = "function NlTPx(mpxGkM) {" fullword ascii
    $s7  = "if(x>=O.length) {break;}" fullword ascii
    $s8  = "yjB = x; break; " fullword ascii
    $s9  = "function OdQF(ZBDLc) {" fullword ascii
    $s10 = "function tQld(wTCRD) {" fullword ascii
    $s11 = "return VfPcu;" fullword ascii
    $s12 = "function Vlyc(BIFTM) {" fullword ascii
    $s13 = "return zzgcWA.position=594-594;" fullword ascii
    $s14 = "function bmikQjXYN(PmuBIYkKqCX) {" fullword ascii
    $s15 = "if (wTCRD == 828-628){return true;} else {return false;}" fullword ascii
    $s16 = "return new ActiveXObject(mpxGkM);" fullword ascii
    $s17 = "function UrgH(scTXH) {" fullword ascii
    $s18 = "function UTRRaSl(Lenf,sOIhP) {" fullword ascii
    $s19 = "return qFgK[WcYNXn[0]];" fullword ascii
    $s20 = "function AiMU(MasJs) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}