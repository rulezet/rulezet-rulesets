rule sig_20160419_94e820da5746e7e82ae31ae5bde31aa0 {
  meta:
    description = "datamaliciousorder - file 20160419_94e820da5746e7e82ae31ae5bde31aa0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3921cd3545d4c99b32ea289abed6a8553db226bba7dcbd936b75f2e1e2908e8"

  strings:
    $s1  = "var Bq = true  , CqAr = UIv[7] + UIv[9] + UIv[11];" fullword ascii
    $s2  = "return AkYRbDB[0] + AkYRbDB[2] + AkYRbDB[4] + \".F\" + AkYRbDB[7] + AkYRbDB[9] + AkYRbDB[12] + AkYRbDB[14];" fullword ascii
    $s3  = "var UIv = (\"2.XMLHTTP atoNJIx mlBuc XML ream St NOnIZOxY AD nZyjwDX O BEBH D\").split(\" \");" fullword ascii
    $s4  = "Flmo.open(QGnrs,jmXwO,false);" fullword ascii
    $s5  = "if(T>=H.length) {break;}" fullword ascii
    $s6  = "function NhYVvI(GlOA,JOTZge) {" fullword ascii
    $s7  = "return tYBKMa[gwbM[823-823]]=791-791;" fullword ascii
    $s8  = "function nGVd(uRojF) {" fullword ascii
    $s9  = "function fukzvnR(tpcx) {" fullword ascii
    $s10 = "function yKSfju(oWTpObV) {" fullword ascii
    $s11 = "if (TSDTC > 176742-577){return true;} else {return false;}" fullword ascii
    $s12 = "return etBEINa;" fullword ascii
    $s13 = "function AZqMTlyD(dVGt) {" fullword ascii
    $s14 = "return PunjN;" fullword ascii
    $s15 = "function RdkV(TSDTC) {" fullword ascii
    $s16 = "function yLQjmBSnv(KNYdD) {" fullword ascii
    $s17 = "function INUw(eDnkW) {" fullword ascii
    $s18 = "function eVAZL(HlO,aTmFB) {" fullword ascii
    $s19 = "HnX = T; break; " fullword ascii
    $s20 = "function rlIk(oRBCe) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}