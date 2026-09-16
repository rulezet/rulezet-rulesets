rule sig_20160308_702c988d8d85fe9380ece8daba637e85 {
  meta:
    description = "datamaliciousorder - file 20160308_702c988d8d85fe9380ece8daba637e85.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2217778a1a00380c2d11227c788889e67d70a4eba1e5acbd6d4f2876160f8e13"

  strings:
    $s1  = "function TYeyePIj() {" fullword ascii
    $s2  = "var EA = true  , ldSl = qwb[7] + qwb[9] + qwb[11];" fullword ascii
    $s3  = "return rimCFpd[0] + rimCFpd[2] + rimCFpd[4] + \".F\" + rimCFpd[7] + rimCFpd[9] + rimCFpd[12] + rimCFpd[14];" fullword ascii
    $s4  = "eCWdp.open(iZoDv,ELajS,false);" fullword ascii
    $s5  = "var qwb = (\"2.XMLHTTP kUBasBk EyGMm XML ream St YczghqHh AD yTrghEf O jiYO D\").split(\" \");" fullword ascii
    $s6  = "return QDr.size;" fullword ascii
    $s7  = "if(J>=S.length) {break;}" fullword ascii
    $s8  = "function XYot(ykYjr) {" fullword ascii
    $s9  = "function iKTnmkvzw(CtFIsYRnZXp) {" fullword ascii
    $s10 = "if (Nfpiy > 166290-308){return true;} else {return false;}" fullword ascii
    $s11 = "return hN.ExpandEnvironmentStrings(DmCGd[6]+DmCGd[7]+DmCGd[8]);" fullword ascii
    $s12 = "function jFpD(kPFKD,bCqnJ) {" fullword ascii
    $s13 = "return HmOp.responseBody;" fullword ascii
    $s14 = "function zMeN(ZGoKt) {" fullword ascii
    $s15 = "function bGixDOA(JBkY) {" fullword ascii
    $s16 = "if (h >= kalLk.length) {break;}" fullword ascii
    $s17 = "return iJZbF;" fullword ascii
    $s18 = "function imZqoKIu(QDr) {" fullword ascii
    $s19 = "function CmcQkPSms(WTbcz,AKqty,hyUun,hXar) {" fullword ascii
    $s20 = "return ODkuj.status;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}