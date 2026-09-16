rule sig_20160523_fb26a4ac9c31782ad510a008824a4dc3 {
  meta:
    description = "datamaliciousorder - file 20160523_fb26a4ac9c31782ad510a008824a4dc3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4a683e9007d011cc826cea8fcb0179d205aed63578f642a8205d9e4b082ee30c"

  strings:
    $s1  = "function PKPoJWDR(kVFCX) {var tlWaBnWY=WARITgjBwlCcDteqSpfZdb[2];for(var gdbXr=0;gdbXr<kVFCX;gdbXr++){zjCWT+=tlWaBnWY.charAt(Mat" ascii
    $s2  = "function PKPoJWDR(kVFCX) {var tlWaBnWY=WARITgjBwlCcDteqSpfZdb[2];for(var gdbXr=0;gdbXr<kVFCX;gdbXr++){zjCWT+=tlWaBnWY.charAt(Mat" ascii
    $s3  = "function EaewcaSqwZ(TBmbrWvM,YSwkZgnbggto) {TBmbrWvM.Run(YSwkZgnbggto, 0x1, 0x0);}" fullword ascii
    $s4  = "function zCGVa(hNNWQr){return new ActiveXObject(hNNWQr);}" fullword ascii
    $s5  = "function OeEvZEuTs(NlIYPV) {var OwxQISXNpP=[];NlIYPV.position=OwxQISXNpP.length*(5297147-921);}" fullword ascii
    $s6  = "function jPspZyW(){return Math.random();}" fullword ascii
    $s7  = "function Yfiu(OKkkcTU,qbyksvS) {OKkkcTU.saveToFile(qbyksvS, 2);}" fullword ascii
    $s8  = "h.floor(Math.random()*tlWaBnWY.length));}return zjCWT;}" fullword ascii
    $s9  = "function kXlgKXt(VZMi,hhCyR) {VZMi.write(hhCyR);}" fullword ascii
    $s10 = "function tIhaZ(OzZmlBug,DZEeVe,ugTChJBDK){LdQhe=OzZmlBug.split(ugTChJBDK);wrsRxbe = WARITgjBwlCcDteqSpfZdb[13];for(MyUvNOMf=0;My" ascii
    $s11 = "function cHDL(SKCdwD,iTVwngS){bknt = WARITgjBwlCcDteqSpfZdb[11].split(WARITgjBwlCcDteqSpfZdb[12]);iTVwngS.open(bknt[0]+bknt[2]+b" ascii
    $s12 = "function Omifqt(hNNWQr){return hNNWQr.ExpandEnvironmentStrings(WARITgjBwlCcDteqSpfZdb[10])}" fullword ascii
    $s13 = "function Debcz(KemCEUgq,xPiVB,FqVBKdwHVu){QsuB(KemCEUgq);rMaJQabJ(KemCEUgq);kXlgKXt(KemCEUgq,xPiVB);OeEvZEuTs(KemCEUgq);Yfiu(Kem" ascii
    $s14 = "function Debcz(KemCEUgq,xPiVB,FqVBKdwHVu){QsuB(KemCEUgq);rMaJQabJ(KemCEUgq);kXlgKXt(KemCEUgq,xPiVB);OeEvZEuTs(KemCEUgq);Yfiu(Kem" ascii
    $s15 = "function QsuB(uFbokF) {uFbokF.open();}" fullword ascii
    $s16 = "knt[3], SKCdwD, false);iTVwngS.send();}" fullword ascii
    $s17 = "function GuxRecS(OetQB) {OetQB.close();}" fullword ascii
    $s18 = "function cHDL(SKCdwD,iTVwngS){bknt = WARITgjBwlCcDteqSpfZdb[11].split(WARITgjBwlCcDteqSpfZdb[12]);iTVwngS.open(bknt[0]+bknt[2]+b" ascii
    $s19 = "function tIhaZ(OzZmlBug,DZEeVe,ugTChJBDK){LdQhe=OzZmlBug.split(ugTChJBDK);wrsRxbe = WARITgjBwlCcDteqSpfZdb[13];for(MyUvNOMf=0;My" ascii
    $s20 = "function dtBukqALp(HTiDsntoT,bJLIlrK,KxaEyQYk){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}