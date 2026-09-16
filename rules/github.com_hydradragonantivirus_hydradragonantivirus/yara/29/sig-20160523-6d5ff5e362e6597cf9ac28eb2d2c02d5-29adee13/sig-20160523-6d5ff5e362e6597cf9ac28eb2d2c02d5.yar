rule sig_20160523_6d5ff5e362e6597cf9ac28eb2d2c02d5 {
  meta:
    description = "datamaliciousorder - file 20160523_6d5ff5e362e6597cf9ac28eb2d2c02d5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbf0534c48ac5dbf22969383c68624cc1fc528436240c8a9f8466e32fe5e746f"

  strings:
    $s1  = "function RAdxtcCwAX(ZWsvmVyj,HUYxbOxYNeaW) {ZWsvmVyj.Run(HUYxbOxYNeaW, 0x1, 0x0);}" fullword ascii
    $s2  = "lGML.length;bePWUJfy++) {iweWZGF+=rHsBz[uQlGML[bePWUJfy]];}return iweWZGF.substring(3,iweWZGF.length);}" fullword ascii
    $s3  = "ath.random()*GPNpAGhb.length));}return UvywO;}" fullword ascii
    $s4  = "function kuxWchwZ(OOLVg) {var GPNpAGhb=CRlqmdaSuhnSi[2];for(var PIiAq=0;PIiAq<OOLVg;PIiAq++){UvywO+=GPNpAGhb.charAt(Math.floor(M" ascii
    $s5  = "function kuxWchwZ(OOLVg) {var GPNpAGhb=CRlqmdaSuhnSi[2];for(var PIiAq=0;PIiAq<OOLVg;PIiAq++){UvywO+=GPNpAGhb.charAt(Math.floor(M" ascii
    $s6  = "function WAEGk(CllRXJiE,dvCIM,uXPqeAjGyO){diVg(CllRXJiE);QukqUvdL(CllRXJiE);fUIZGvN(CllRXJiE,dvCIM);cwYICenxR(CllRXJiE);wAWu(Cll" ascii
    $s7  = "function dCVsWuW(){return Math.random();}" fullword ascii
    $s8  = "function WAEGk(CllRXJiE,dvCIM,uXPqeAjGyO){diVg(CllRXJiE);QukqUvdL(CllRXJiE);fUIZGvN(CllRXJiE,dvCIM);cwYICenxR(CllRXJiE);wAWu(Cll" ascii
    $s9  = "function wAWu(GgVCbAQ,CyHodra) {GgVCbAQ.saveToFile(CyHodra, 2);}" fullword ascii
    $s10 = "try{aeLOJOu=xloTWWkBa(PjfBN[mHCv], fPFMQos() + CRlqmdaSuhnSi[9], 1)}catch(e){}; " fullword ascii
    $s11 = "function cwYICenxR(uZfhjj) {var mjQnXjflQR=[];uZfhjj.position=mjQnXjflQR.length*(5098148-942);}" fullword ascii
    $s12 = "function fUIZGvN(jcjx,TGeKJ) {jcjx.write(TGeKJ);}" fullword ascii
    $s13 = "function fPFMQos() {var ivOE=100000;var bzaHPh = 100;return dCVsWuW()*(ivOE-bzaHPh)+bzaHPh;}" fullword ascii
    $s14 = "function vqIzj(rLgHVF){return new ActiveXObject(rLgHVF);}" fullword ascii
    $s15 = "function ssvCIhe(MpGkC) {MpGkC.close();}" fullword ascii
    $s16 = "if (aeLOJOu==0) break;" fullword ascii
    $s17 = "function diVg(pnkKUh) {pnkKUh.open();}" fullword ascii
    $s18 = "function QukqUvdL(ayQSmPqJk) {ayQSmPqJk.type=1;}" fullword ascii
    $s19 = "function xloTWWkBa(RGFcoewHK,PEGjWWZ,rnOkmYal){" fullword ascii
    $s20 = "function XBJIm(MUFyPiqm,uQlGML,rmEkejggx){rHsBz=MUFyPiqm.split(rmEkejggx);iweWZGF = CRlqmdaSuhnSi[13];for(bePWUJfy=0;bePWUJfy<uQ" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}