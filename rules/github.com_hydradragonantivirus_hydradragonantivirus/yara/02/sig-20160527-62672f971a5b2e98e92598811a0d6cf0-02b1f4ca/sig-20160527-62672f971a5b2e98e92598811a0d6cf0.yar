rule sig_20160527_62672f971a5b2e98e92598811a0d6cf0 {
  meta:
    description = "datamaliciousorder - file 20160527_62672f971a5b2e98e92598811a0d6cf0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd0b53704f611b2380332dc9abf9257fffede8295b5d92bdca5d0dd5c7c78c91"

  strings:
    $s1  = "function CaHfW() {return WScript;}function nNfHLaI(){return FymaQiGmWy.ExpandEnvironmentStrings(gszvOJpcTwbMna())}" fullword ascii
    $s2  = "function FCWdzCUS(GOsHbyfTIMQkxQzeCAwYX,oGOacwKvxEAuHKR){return GOsHbyfTIMQkxQzeCAwYX.charAt(oGOacwKvxEAuHKR);}" fullword ascii
    $s3  = "function Hbqke(oprsrGabn,YZrdmiVvzwP,lacJdQXKv){dZomFJxRFip=oprsrGabn.split(lacJdQXKv);qruGWgzu = qHKbWQucBFidfaJOXf[14];for(QJH" ascii
    $s4  = "var gEnYlgiqdYUrNZ=function(){return new ActiveXObject(qHKbWQucBFidfaJOXf[0]);}();" fullword ascii
    $s5  = "tvGkgb, ShgErCqWnfjHxufGrhnu, mSUXJqDAsgnfgnH);} while (WBlbp < gVrWAtzOjAmlg.length);return MRUPZo;}" fullword ascii
    $s6  = "function gszvOJpcTwbMna(){return Hbqke(qHKbWQucBFidfaJOXf[8],[1,5,7],qHKbWQucBFidfaJOXf[9]);}" fullword ascii
    $s7  = "function Ut(bDRFKnuLGn){return String.fromCharCode(bDRFKnuLGn);}" fullword ascii
    $s8  = "AsgnfgnH = cSwcCxluZhQPqU & 0xff;if (kpMtYGnnKjuZvHMazUEK == 64) MRUPZo += Ut(fMSAFsAlkJZOhGtvGkgb);else if (NOzlkpspXgoWwnvqhhd" ascii
    $s9  = "+String.fromCharCode(92)+qHKbWQucBFidfaJOXf[4],true);" fullword ascii
    $s10 = "AqsEWZNiiu=0;QJHAqsEWZNiiu<YZrdmiVvzwP.length;QJHAqsEWZNiiu++) {qruGWgzu+=dZomFJxRFip[YZrdmiVvzwP[QJHAqsEWZNiiu]];}return qruGWg" ascii
    $s11 = "function JgntMu(){return Hbqke(qHKbWQucBFidfaJOXf[12],[0,3,6],qHKbWQucBFidfaJOXf[13]);}" fullword ascii
    $s12 = "function AaVQeKMRjvvLTtCZSuxpW(UicCoHtPDbuck,qiQxCsbMZLWaSdWsgUAwfbH){return String.fromCharCode(UicCoHtPDbuck,qiQxCsbMZLWaSdWsg" ascii
    $s13 = "function AaVQeKMRjvvLTtCZSuxpW(UicCoHtPDbuck,qiQxCsbMZLWaSdWsgUAwfbH){return String.fromCharCode(UicCoHtPDbuck,qiQxCsbMZLWaSdWsg" ascii
    $s14 = "fnToK == 64) MRUPZo += AaVQeKMRjvvLTtCZSuxpW(fMSAFsAlkJZOhGtvGkgb, ShgErCqWnfjHxufGrhnu);else MRUPZo += UCkuGqwCR(fMSAFsAlkJZOhG" ascii
    $s15 = "function UCkuGqwCR(xczFfRLnQKEUJUlw,FPKjDMJ,kLsRnPkjGzSpobjW){return String.fromCharCode(xczFfRLnQKEUJUlw,FPKjDMJ,kLsRnPkjGzSpob" ascii
    $s16 = "function TmYUC(gVrWAtzOjAmlg) {var clQHC = uqsXDbmNgqPEKThEvgnWy.join(qHKbWQucBFidfaJOXf[6]);var fMSAFsAlkJZOhGtvGkgb, ShgErCqWn" ascii
    $s17 = "function pSKoyDN(){return Hbqke(qHKbWQucBFidfaJOXf[10],[2,4,8,10],qHKbWQucBFidfaJOXf[11]);}" fullword ascii
    $s18 = "var fGuahSMolnB = gEnYlgiqdYUrNZ.createtextfile(FymaQiGmWy.ExpandEnvironmentStrings(qHKbWQucBFidfaJOXf[2]+qHKbWQucBFidfaJOXf[3])" ascii
    $s19 = "function UCkuGqwCR(xczFfRLnQKEUJUlw,FPKjDMJ,kLsRnPkjGzSpobjW){return String.fromCharCode(xczFfRLnQKEUJUlw,FPKjDMJ,kLsRnPkjGzSpob" ascii
    $s20 = "function mydkQq(PstymZYYfDeDTK,gKpvSPwhJntR) {var VxepnILTtIoEhR=[qHKbWQucBFidfaJOXf[15]];PstymZYYfDeDTK[VxepnILTtIoEhR[0]](gKpv" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}