rule sig_20160405_976271953c04bad8333bce18dc48d4a4 {
  meta:
    description = "datamaliciousorder - file 20160405_976271953c04bad8333bce18dc48d4a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82e4c891733fb576dd16ab446806061c1c15cf82be5346a1034ea7c5ebd43c3d"

  strings:
    $s1  = "return gDRTZlo[0] + gDRTZlo[2] + gDRTZlo[4] + \".F\" + gDRTZlo[7] + gDRTZlo[9] + gDRTZlo[12] + gDRTZlo[14];" fullword ascii
    $s2  = "var YO = true  , yWMY = bxN[7] + bxN[9] + bxN[11];" fullword ascii
    $s3  = "var bxN = (\"2.XMLHTTP pEWhLSQ kKCSb XML ream St wmUPVrzZ AD AyMJBOR O vElO D\").split(\" \");" fullword ascii
    $s4  = "mYKE.open(fsmJJ,jDdJc,false);" fullword ascii
    $s5  = "if(o>=e.length) {break;}" fullword ascii
    $s6  = "function UBYMa(mAclKO) {" fullword ascii
    $s7  = "function MQLD(HmIAf) {" fullword ascii
    $s8  = "function tnBylzGhh(jwuDL) {" fullword ascii
    $s9  = "function bXiqH(JPlUFU) {" fullword ascii
    $s10 = "return QrAYCEO;" fullword ascii
    $s11 = "return HvUl;" fullword ascii
    $s12 = "function xyhU(fiwrM,ctMFP) {" fullword ascii
    $s13 = "function lbENaBN(rusq) {" fullword ascii
    $s14 = "function Onvo(KOXtv) {" fullword ascii
    $s15 = "return HzOvL;" fullword ascii
    $s16 = "function uGuQPEfVM(gWEYyoMYgwE) {" fullword ascii
    $s17 = "return IdAVZ.status;" fullword ascii
    $s18 = "if (bkKzK == 756-556){return true;} else {return false;}" fullword ascii
    $s19 = "function aPAtubc(DykO,hUfAy) {" fullword ascii
    $s20 = "if (W >= KOXtv.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}