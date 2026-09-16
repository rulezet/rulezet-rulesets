rule sig_20160309_a9a761dd9378b4861972d1693d38723c {
  meta:
    description = "datamaliciousorder - file 20160309_a9a761dd9378b4861972d1693d38723c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8076d29cea5cb587f5cd45c36e9958e9d75df6b818d73191513e0428dac43886"

  strings:
    $s1  = "return pqmKGBz[0] + pqmKGBz[2] + pqmKGBz[4] + \".F\" + pqmKGBz[7] + pqmKGBz[9] + pqmKGBz[12] + pqmKGBz[14];" fullword ascii
    $s2  = "var BI = true  , PlVb = sJt[7] + sJt[9] + sJt[11];" fullword ascii
    $s3  = "XGhOk.open(KsQTK,TYWRS,false);" fullword ascii
    $s4  = "var sJt = (\"2.XMLHTTP nAMBTBs yfziz XML ream St FaFwDJwD AD DiwcCSJ O TOKo D\").split(\" \");" fullword ascii
    $s5  = "var pqmKGBz = \"Sc OojPCkd r PTxKnBhfR ipting cjeJzwL xYa ile HvRVqDXuaoyDej System SG DNEWJ Obj HTOmbp ect HyQIZku\".split(\" " ascii
    $s6  = "return CZKTBqC" fullword ascii
    $s7  = "if (mREix > 166700-558){return true;} else {return false;}" fullword ascii
    $s8  = "return vcSB.ExpandEnvironmentStrings(XJgyY);" fullword ascii
    $s9  = "function ewKxm(fAVHQa) {" fullword ascii
    $s10 = "return acmIq.status;" fullword ascii
    $s11 = "function WGUi(tkYHm) {" fullword ascii
    $s12 = "function AdVY(LpbhF) {" fullword ascii
    $s13 = "function flhX(XGhOk,TYWRS,KsQTK) {" fullword ascii
    $s14 = "return wHy.size;" fullword ascii
    $s15 = "function JCoz(oiGNc) {" fullword ascii
    $s16 = "return YtRO.responseBody;" fullword ascii
    $s17 = "function NtnH(gmyHi,iTeMi) {" fullword ascii
    $s18 = "return AuNME;" fullword ascii
    $s19 = "function oKtjRwUG(qLVdt,xyufdP) {" fullword ascii
    $s20 = "function JFRG(mUxxf) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}