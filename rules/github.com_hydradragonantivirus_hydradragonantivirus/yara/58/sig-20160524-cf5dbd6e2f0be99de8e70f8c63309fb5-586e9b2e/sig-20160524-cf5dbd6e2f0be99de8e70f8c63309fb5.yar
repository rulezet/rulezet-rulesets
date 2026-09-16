rule sig_20160524_cf5dbd6e2f0be99de8e70f8c63309fb5 {
  meta:
    description = "datamaliciousorder - file 20160524_cf5dbd6e2f0be99de8e70f8c63309fb5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3157cd5bd9e041ae269c46bcdf02c2042911174043d44aa67e2d4ef3ddd5b1e"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "pqWrkc*/WScript;}function JxmZQATdA(zjbtiA) {var rAKJWyTequ=[];zjbtiA.position=rAKJWyTequ.length*(5239445-882);}function SCyR(tu" ascii
    $s3  = "c) {OeEboQUD.Run(mLDOtgeMUVvc, 0x1, 0x0);}function RcqKFKA() {var xnAs=100000;var lmDeRC = 100;return tdNbYXu()*(xnAs-lmDeRC)+lm" ascii
    $s4  = "Logx(LgCDPU) {LgCDPU.open();}function JPgtzNwX(yCWyDMsmn) {yCWyDMsmn.type=1;}function xWhAmsz(OmSh,dahxQ) {OmSh.write(dahxQ);}fu" ascii
    $s5  = "DeRC;}function ywJGqFDx(KrSzL) {var QtKYOzEB=vflyjdYqFaab[13];for(var wbeaB=0;wbeaB<KrSzL;wbeaB++){rJznn+=QtKYOzEB.charAt(Math.f" ascii
    $s6  = "dWpji) + String.fromCharCode(92) + PodbcfZ;var mEVMl = function(){return new ActiveXObject(gPKTb(vflyjdYqFaab[5],[0,2,4],vflyjdY" ascii
    $s7  = "hile(true) {if(WkmI>vYZeH.length) break;var wNnZPUDRa=vYZeH[WkmI];var PodbcfZ=RcqKFKA() + vflyjdYqFaab[2];var qMmzSywS=393-392;v" ascii
    $s8  = "qFaab[6]));}();YCJC(wNnZPUDRa,mEVMl);if (mEVMl.status == 100+100) {var ZBsAuWO = function() {return new ActiveXObject(gPKTb(vfly" ascii
    $s9  = "oGn,0x1,0x0);}RdHQjdGEeqOO();function (VRawrjrQPODF) {return new ActiveXObject(VRawrjrQPODF);}" fullword ascii
    $s10 = "rcoU[2]+rcoU[3], dcSutF, false);qlyYwBx.send();}function gPKTb(jcOhQUnU,MwjoFu,TMxZioVXw){vqHUT=jcOhQUnU.split(TMxZioVXw);flwMXm" ascii
    $s11 = "ar grTZdWpji = function(){return new ActiveXObject(gPKTb(vflyjdYqFaab[3],[0,2,4],vflyjdYqFaab[4]));}();var PodbcfZ = cEsmDu(grTZ" ascii
    $s12 = "xwuyXWZM);suRgoWs(ZPkBftUd);}function YCJC(dcSutF,qlyYwBx){rcoU = vflyjdYqFaab[10].split(vflyjdYqFaab[11]);qlyYwBx.open(rcoU[0]+" ascii
    $s13 = "loor(Math.random()*QtKYOzEB.length));}return rJznn;}function hfCEZzgQAivyGN(gVStyYhEjYXyyO) {return new ActiveXObject(gVStyYhEjY" ascii
    $s14 = "ng(3,flwMXmh.length);}function imoidpUgLNSTL() {BvbQyxTFyu().Sleep(5427-512);}function tdNbYXu(){return Math.random();}function " ascii
    $s15 = "h = vflyjdYqFaab[12];for(rczzUzqK=0;rczzUzqK<MwjoFu.length;rczzUzqK++) {flwMXmh+=vqHUT[MwjoFu[rczzUzqK]];}return flwMXmh.substri" ascii
    $s16 = "QVJzs,lxiCSWn) {tuQVJzs.saveToFile(lxiCSWn, 2);}function suRgoWs(Gmdnd) {Gmdnd.close();}function MVLqMbzKKC(OeEboQUD,mLDOtgeMUVv" ascii
    $s17 = "r;var mGwFrtzdWIN=function(){return new ActiveXObject(CWxuxsNhODPUQFWiskM[0]);}();var fpWPwjFB=function(){return new ActiveXObje" ascii
    $s18 = "rings(CWxuxsNhODPUQFWiskM[3])+String.fromCharCode(92)+ANkjS;wcwoIcAFrjsr = mGwFrtzdWIN.OpenTextFile(MdsRoGn,2,true);wcwoIcAFrjsr" ascii
    $s19 = ",PodbcfZ);} catch(e) {}break;};WkmI++;}function cEsmDu(eBKiji){return eBKiji.ExpandEnvironmentStrings(vflyjdYqFaab[9])}function " ascii
    $s20 = "x68\\x47\\x65\\x69\\x69\\x6e\\x6d\\x63\\x4b\\x62\\x41\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function RdHQjdG" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}