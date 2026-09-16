rule sig_20160307_4ad5e2238967beb727689c704fb9c7a7 {
  meta:
    description = "datamaliciousorder - file 20160307_4ad5e2238967beb727689c704fb9c7a7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "129b3b3504c7c8d1e6a5b9c6f4d87b312e5d1118fbca6390440c22d151c19b7d"

  strings:
    $s1  = "var xm = true  , KyGE = AsX[7] + AsX[9] + AsX[11];" fullword ascii
    $s2  = "return KoiXZSj[0] + KoiXZSj[2] + KoiXZSj[4] + \".F\" + KoiXZSj[7] + KoiXZSj[9] + KoiXZSj[12] + KoiXZSj[14];" fullword ascii
    $s3  = "var KoiXZSj = \"Sc WYbLEnT r unutTxSVp ipting KPmkpde fou ile lhaRTtbedvIdVa System Ze yuyad Obj LdUIJn ect CqBqhvD\".split(\" " ascii
    $s4  = "vPKSm.open(HLDFX,Nbtof,false);" fullword ascii
    $s5  = "var AsX = (\"2.XMLHTTP ndgHqrk kMedf XML ream St vQZBSgGP AD dSgTppi O Cntc D\").split(\" \");" fullword ascii
    $s6  = "if (pVrbk == 496-296){return true;} else {return false;}" fullword ascii
    $s7  = "function BcLksELt(atL) {" fullword ascii
    $s8  = "function MPaN(pVrbk) {" fullword ascii
    $s9  = "return new ActiveXObject(RfSQle);" fullword ascii
    $s10 = "if (ssWnG > 160327-647){return true;} else {return false;}" fullword ascii
    $s11 = "function mhWRQ(RfSQle) {" fullword ascii
    $s12 = "return viHne;" fullword ascii
    $s13 = "function PymO(CULMz) {" fullword ascii
    $s14 = "if (J >= GKVAK.length) {break;}" fullword ascii
    $s15 = "function pcGNbJrTv(UaYAkcvbyKI) {" fullword ascii
    $s16 = "function pLiu(GKVAK) {" fullword ascii
    $s17 = "function ojuj(pBtLh,KviCk) {" fullword ascii
    $s18 = "return atL.size;" fullword ascii
    $s19 = "if (((new Date())>0,7215120888)) {" fullword ascii
    $s20 = "function VDjq(ssWnG) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}