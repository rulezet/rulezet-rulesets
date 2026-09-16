rule sig_20160524_808b55c7fa95e92c45bf49cb1226dc50 {
  meta:
    description = "datamaliciousorder - file 20160524_808b55c7fa95e92c45bf49cb1226dc50.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33f57efd001abf30f33bed859e5e7d7fce331a5a1c8385db98332be25ef03735"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = ");}function VQIWeYk(AERjK) {AERjK.close();}function afWZwapqxo(GkigMDhn,aVBVojUPTSqh) {GkigMDhn.Run(aVBVojUPTSqh, 0x1, 0x0);}fun" ascii
    $s3  = "cAUeuryZidqzvXoDOJJHrzuMJfNpULGpEeqjSuJXpsddYlqzAKOJZZpHZRkPHxsiABeiKqnPPBkAVtMpFEnFatDvK*/WScript;}function tcmynEUgV(NbIFwD) {" ascii
    $s4  = "CJbg=Kfxhc[vmvW];var GKuzhVh=VAftAtL() + MsDaKjwVUlXNVCYkLXuCYClt[2];var ASHLpWMf=672-671;var vgCOZHVKF = function(){return new " ascii
    $s5  = "ng.fromCharCode(92) + GKuzhVh;var geRmL = function(){return new ActiveXObject(azvDi(MsDaKjwVUlXNVCYkLXuCYClt[5],[0,2,4],MsDaKjwV" ascii
    $s6  = "yjmjkY.length;lIIxXHSs++) {TVLFeaG+=oYYPp[yjmjkY[lIIxXHSs]];}return TVLFeaG.substring(3,TVLFeaG.length);}function xbjNcyUPSnaVh(" ascii
    $s7  = "DeW,JJrtm);tcmynEUgV(vMoPKDeW);pcZs(vMoPKDeW,bHTJfdHSTl);VQIWeYk(vMoPKDeW);}function ugOj(rqQDkP,wxktGwd){vRGa = MsDaKjwVUlXNVCY" ascii
    $s8  = "h));}return pRpCC;}function RqczKzXqekmsfJ(NEsHTyVqvYuuLD) {return new ActiveXObject(NEsHTyVqvYuuLD);}');var WyDkHgbBFImRMFpLwv=" ascii
    $s9  = "tStrings(MsDaKjwVUlXNVCYkLXuCYClt[9])}function hzLPO(vMoPKDeW,JJrtm,bHTJfdHSTl){vMoPKDeW.open();NMREKgDt(vMoPKDeW);XawpRuV(vMoPK" ascii
    $s10 = "kLXuCYClt[10].split(MsDaKjwVUlXNVCYkLXuCYClt[11]);wxktGwd.open(vRGa[0]+vRGa[2]+vRGa[3], rqQDkP, false);wxktGwd.send();}function " ascii
    $s11 = ") {HVuHWPmCEA().Sleep(3437-429);}function yYMzKKh(){return Math.random();}function dqfL(jOnIHc) {jOnIHc.open();}function NMREKgD" ascii
    $s12 = "ction VAftAtL() {var jYmQ=100000;var wWSNDw = 100;return yYMzKKh()*(jYmQ-wWSNDw)+wWSNDw;}function vtEgGbXc(MBGRy) {var meDaaoQf=" ascii
    $s13 = "1,0x0);}XzjhPi();function (mSNsWZDiYV) {return new ActiveXObject(mSNsWZDiYV);}" fullword ascii
    $s14 = "CgAbfqMk;var tNybpbkcBs=function(){return new ActiveXObject(wfbjXkPdSJpu[0]);}();var OojfrrdqtZsa=function(){return new ActiveXO" ascii
    $s15 = "UlXNVCYkLXuCYClt[6]));}();ugOj(BLYdRCJbg,geRmL);if (geRmL.status == 100+100) {var ONBVYRV = function() {return new ActiveXObject" ascii
    $s16 = "t(JDjUPnDeH) {JDjUPnDeH.type=1;}function XawpRuV(sGcY,WDQEF) {sGcY.write(WDQEF);}function HVuHWPmCEA() {return/*wCYzcTULLmKIBUnp" ascii
    $s17 = "65\\x69\\x56\\x41\\x74\\x43\\x6d\\x45\\x66\\x52\\x50\\x69\\x67\\x6c\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];fu" ascii
    $s18 = "= [MsDaKjwVUlXNVCYkLXuCYClt[0], MsDaKjwVUlXNVCYkLXuCYClt[1]];var vmvW=982-982;while(true) {if(vmvW>Kfxhc.length) break;var BLYdR" ascii
    $s19 = "s(wfbjXkPdSJpu[3])+String.fromCharCode(92)+AoQCm;uDsqvECgAbfqMk = tNybpbkcBs.OpenTextFile(qqGhONynKf,2,true);uDsqvECgAbfqMk.Writ" ascii
    $s20 = "var JbWbnufsZw=[];NbIFwD.position=JbWbnufsZw.length*(9000027-694);}function pcZs(tbRUHOG,nYpXiKb) {tbRUHOG.saveToFile(nYpXiKb, 2" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}