rule sig_20160523_181ba6c1c53d5eb7958fed223c0bea45 {
  meta:
    description = "datamaliciousorder - file 20160523_181ba6c1c53d5eb7958fed223c0bea45.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d964bdc86c31aa19a73963a67520da8ee154f988f741ca6474bf9bb5cd4821b4"

  strings:
    $s1  = "function phXIhrKLhv(MNSrwuvZ,RVwYtDVwQAKs) {MNSrwuvZ.Run(RVwYtDVwQAKs, 0x1, 0x0);}" fullword ascii
    $s2  = "function XzcGlMXq(QjZXU) {var gqAWsCCh=GzRCLwoEiCXOxPbJFtZcFm[13];for(var OAyzT=0;OAyzT<QjZXU;OAyzT++){Bzhag+=gqAWsCCh.charAt(Ma" ascii
    $s3  = "function UohngsEmYR() {return/*xBeMtBNdpkeYWstkCZSxmPHqcSNKSpeElrvGFAcTKhsIvbRorHKwkzcafYhgZCgemBSrYkPEzxQMVbWzusUkCQnjVXrHeYsIW" ascii
    $s4  = "function XzcGlMXq(QjZXU) {var gqAWsCCh=GzRCLwoEiCXOxPbJFtZcFm[13];for(var OAyzT=0;OAyzT<QjZXU;OAyzT++){Bzhag+=gqAWsCCh.charAt(Ma" ascii
    $s5  = "function SPYPUyU(yILag) {yILag.close();}" fullword ascii
    $s6  = "function hpMjP(bUxcSkHV,zUnNO,PkgLTmmKgz){enjd(bUxcSkHV);pesECQIy(bUxcSkHV);swZzwMx(bUxcSkHV,zUnNO);uBYphiaBT(bUxcSkHV);MUzu(bUx" ascii
    $s7  = "function uBYphiaBT(DjkEAA) {var ubhUlptqXY=[];DjkEAA.position=ubhUlptqXY.length*(5937953-722);}" fullword ascii
    $s8  = "function VhhO(prFxWn,WlTBBYh){iMGi = GzRCLwoEiCXOxPbJFtZcFm[10].split(GzRCLwoEiCXOxPbJFtZcFm[11]);WlTBBYh.open(iMGi[0]+iMGi[2]+i" ascii
    $s9  = "function gvSdh(medjuC){return new ActiveXObject(medjuC);}" fullword ascii
    $s10 = "function enjd(gxEoWk) {gxEoWk.open();}" fullword ascii
    $s11 = "th.floor(Math.random()*gqAWsCCh.length));}return Bzhag;}" fullword ascii
    $s12 = "MGi[3], prFxWn, false);WlTBBYh.send();}" fullword ascii
    $s13 = "function VhhO(prFxWn,WlTBBYh){iMGi = GzRCLwoEiCXOxPbJFtZcFm[10].split(GzRCLwoEiCXOxPbJFtZcFm[11]);WlTBBYh.open(iMGi[0]+iMGi[2]+i" ascii
    $s14 = "function oMIVI(xYpyogRv,BoeZpW,RGItpYrLI){UIDWb=xYpyogRv.split(RGItpYrLI);IavQwNN = GzRCLwoEiCXOxPbJFtZcFm[12];for(qlFDxqsv=0;ql" ascii
    $s15 = "function pesECQIy(xIfqxcJxV) {xIfqxcJxV.type=1;}" fullword ascii
    $s16 = "function oMIVI(xYpyogRv,BoeZpW,RGItpYrLI){UIDWb=xYpyogRv.split(RGItpYrLI);IavQwNN = GzRCLwoEiCXOxPbJFtZcFm[12];for(qlFDxqsv=0;ql" ascii
    $s17 = "function hpMjP(bUxcSkHV,zUnNO,PkgLTmmKgz){enjd(bUxcSkHV);pesECQIy(bUxcSkHV);swZzwMx(bUxcSkHV,zUnNO);uBYphiaBT(bUxcSkHV);MUzu(bUx" ascii
    $s18 = "function MUzu(CoWIdtG,VTkNikx) {CoWIdtG.saveToFile(VTkNikx, 2);}" fullword ascii
    $s19 = "function nvEDoiLtuIjmd() {UohngsEmYR().Sleep(2314699-612);}" fullword ascii
    $s20 = "function dIqaLA(medjuC){return medjuC.ExpandEnvironmentStrings(GzRCLwoEiCXOxPbJFtZcFm[9])}" fullword ascii

  condition:
    uint16(0) == 0x0c27 and
    8 of them
}