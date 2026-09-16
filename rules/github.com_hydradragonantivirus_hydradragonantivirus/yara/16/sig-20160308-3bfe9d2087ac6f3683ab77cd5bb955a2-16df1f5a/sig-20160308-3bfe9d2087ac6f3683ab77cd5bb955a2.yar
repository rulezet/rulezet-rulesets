rule sig_20160308_3bfe9d2087ac6f3683ab77cd5bb955a2 {
  meta:
    description = "datamaliciousorder - file 20160308_3bfe9d2087ac6f3683ab77cd5bb955a2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ea724a0bffc3b1cc7e9f33440aa94e2008c30ee204c6dc3c9c27c5f6e2f3110"

  strings:
    $s1  = "var rm = true  , jUjF = CVV[7] + CVV[9] + CVV[11];" fullword ascii
    $s2  = "return qitgpgb[0] + qitgpgb[2] + qitgpgb[4] + \".F\" + qitgpgb[7] + qitgpgb[9] + qitgpgb[12] + qitgpgb[14];" fullword ascii
    $s3  = "PBsvG.open(EizGs,jgmhe,false);" fullword ascii
    $s4  = "var CVV = (\"2.XMLHTTP iAfskUj GSTkH XML ream St wgBPpacw AD kmHNeMz O RgzG D\").split(\" \");" fullword ascii
    $s5  = "function npxrQXmED(nUJiSTqGUbS) {" fullword ascii
    $s6  = "function ragN(lGQkv,tWFhq) {" fullword ascii
    $s7  = "function cXlI(iIrYp) {" fullword ascii
    $s8  = "return qg.ExpandEnvironmentStrings(aHsmu[6]+aHsmu[7]+aHsmu[8]);" fullword ascii
    $s9  = "function WJwh(VcvXq) {" fullword ascii
    $s10 = "if (orIoB == 646-446){return true;} else {return false;}" fullword ascii
    $s11 = "function qczLxipP() {" fullword ascii
    $s12 = "if (kRwuY > 177335-224){return true;} else {return false;}" fullword ascii
    $s13 = "function qpwhtfNh(EZw) {" fullword ascii
    $s14 = "if (((new Date())>0,7648311888)) {" fullword ascii
    $s15 = "function FAeJ(GjuHV) {" fullword ascii
    $s16 = "return CvWc.responseBody;" fullword ascii
    $s17 = "function nMDZq(hoygZY) {" fullword ascii
    $s18 = "return VcvXq.status;" fullword ascii
    $s19 = "return feCfa;" fullword ascii
    $s20 = "function OlxK(wGltU,usWdD) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}