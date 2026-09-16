rule sig_20160311_2a11d73877ffabea23202390997e8cab {
  meta:
    description = "datamaliciousorder - file 20160311_2a11d73877ffabea23202390997e8cab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a9d0655e2a4509fa89cbc842d5e0a8b472c2cf966cb619e36272fe12ea00546"

  strings:
    $s1  = "return yzNEYrN[0] + yzNEYrN[2] + yzNEYrN[4] + \".F\" + yzNEYrN[7] + yzNEYrN[9] + yzNEYrN[12] + yzNEYrN[14];" fullword ascii
    $s2  = "var sM = true  , WTuL = Yfd[7] + Yfd[9] + Yfd[11];" fullword ascii
    $s3  = "NoZdD.open(AuMze,wTxuj,false);" fullword ascii
    $s4  = "var Yfd = (\"2.XMLHTTP bTkWfEx GUdvW XML ream St PiUxVqQH AD upSOAwZ O CbmR D\").split(\" \");" fullword ascii
    $s5  = "function VOZtFjBWf() {" fullword ascii
    $s6  = "function aGGGSiBdG(UkrXqEUkoHN) {" fullword ascii
    $s7  = "return pLpT.responseBody;" fullword ascii
    $s8  = "return Zagxy.status;" fullword ascii
    $s9  = "function BFuz(yBNkP) {" fullword ascii
    $s10 = "return OTuqN;" fullword ascii
    $s11 = "return nmAJTRY(yE,ZtYUt[301-295]+ZtYUt[397-390]+ZtYUt[931-923]);" fullword ascii
    $s12 = "return rXdKYT.position=923-923;" fullword ascii
    $s13 = "function kPmrWty(pLpT) {" fullword ascii
    $s14 = "function FlNX(NoZdD,wTxuj,AuMze) {" fullword ascii
    $s15 = "function GGfF(SGIgL) {" fullword ascii
    $s16 = "return new ActiveXObject(JDEJPy);" fullword ascii
    $s17 = "function UOPi(KYUpa,pbbGJ) {" fullword ascii
    $s18 = "function GfMOCQsc(mIHVa,Ozjubw) {" fullword ascii
    $s19 = "return IzjGibc" fullword ascii
    $s20 = "if(w>=N.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}