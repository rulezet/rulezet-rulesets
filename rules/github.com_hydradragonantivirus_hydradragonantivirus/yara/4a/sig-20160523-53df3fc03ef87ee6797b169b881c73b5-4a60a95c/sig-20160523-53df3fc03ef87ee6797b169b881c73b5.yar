rule sig_20160523_53df3fc03ef87ee6797b169b881c73b5 {
  meta:
    description = "datamaliciousorder - file 20160523_53df3fc03ef87ee6797b169b881c73b5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d08b6457c368973749643edf73ce2a674867cc35164b7689db5103cf7f0a55c"

  strings:
    $s1  = "function mGLAMPDQpn(vVHtLTbZ,xrgvfrjBGBVJ) {vVHtLTbZ.Run(xrgvfrjBGBVJ, 0x1, 0x0);}" fullword ascii
    $s2  = "function nholfohi(IKywO) {var tRMONqqB=VEnXTCAuRGR[2];for(var QBTsc=0;QBTsc<IKywO;QBTsc++){DHfua+=tRMONqqB.charAt(Math.floor(Mat" ascii
    $s3  = "function nholfohi(IKywO) {var tRMONqqB=VEnXTCAuRGR[2];for(var QBTsc=0;QBTsc<IKywO;QBTsc++){DHfua+=tRMONqqB.charAt(Math.floor(Mat" ascii
    $s4  = "gs.length;TjNrwiiY++) {twHVOMv+=cwDty[VntZgs[TjNrwiiY]];}return twHVOMv.substring(3,twHVOMv.length);}" fullword ascii
    $s5  = "if (PUofrUj==0) break;" fullword ascii
    $s6  = "function hwZOO(LVgGPNpA,GhbPI,iAqUvywOYg){xYIL(LVgGPNpA);cRYjKpxU(LVgGPNpA);ctmHCvv(LVgGPNpA,GhbPI);FmuQGrAlG(LVgGPNpA);JiEd(LVg" ascii
    $s7  = "function nEzQSbk() {var TJQq=100000;var YXOQMu = 100;return MjYbmYV()*(TJQq-YXOQMu)+YXOQMu;}" fullword ascii
    $s8  = "function fBNfP(FMQosi){return new ActiveXObject(FMQosi);}" fullword ascii
    $s9  = "function xYIL(kDWNKf) {kDWNKf.open();}" fullword ascii
    $s10 = "function MjYbmYV(){return Math.random();}" fullword ascii
    $s11 = "try{PUofrUj=goRaPUtnC(djgLN[AMPj], nEzQSbk() + VEnXTCAuRGR[9], 1)}catch(e){}; " fullword ascii
    $s12 = "h.random()*tRMONqqB.length));}return DHfua;}" fullword ascii
    $s13 = "function goRaPUtnC(IuqDXnHBk,QSHfuva,VRnmqzUu){" fullword ascii
    $s14 = "function ctmHCvv(qIzj,rLgHV) {qIzj.write(rLgHV);}" fullword ascii
    $s15 = "function cRYjKpxU(gbfRbqweG) {gbfRbqweG.type=1;}" fullword ascii
    $s16 = "function JiEd(vCIMuXP,qeAjGyO) {vCIMuXP.saveToFile(qeAjGyO, 2);}" fullword ascii
    $s17 = "function FmuQGrAlG(sGSYOP) {var WAEGkCllRX=[];sGSYOP.position=WAEGkCllRX.length*(2465400-715);}" fullword ascii
    $s18 = "function OWAjW(vcVfPqOD,VntZgs,OGnDEjIuV){cwDty=vcVfPqOD.split(OGnDEjIuV);twHVOMv = VEnXTCAuRGR[13];for(TjNrwiiY=0;TjNrwiiY<VntZ" ascii
    $s19 = "function vOEbza(FMQosi){return FMQosi.ExpandEnvironmentStrings(VEnXTCAuRGR[10])}" fullword ascii
    $s20 = "function hwZOO(LVgGPNpA,GhbPI,iAqUvywOYg){xYIL(LVgGPNpA);cRYjKpxU(LVgGPNpA);ctmHCvv(LVgGPNpA,GhbPI);FmuQGrAlG(LVgGPNpA);JiEd(LVg" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}