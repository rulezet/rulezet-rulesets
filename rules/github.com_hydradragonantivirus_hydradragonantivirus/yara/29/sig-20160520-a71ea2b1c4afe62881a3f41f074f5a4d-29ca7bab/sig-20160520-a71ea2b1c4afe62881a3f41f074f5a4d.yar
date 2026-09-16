rule sig_20160520_a71ea2b1c4afe62881a3f41f074f5a4d {
  meta:
    description = "datamaliciousorder - file 20160520_a71ea2b1c4afe62881a3f41f074f5a4d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f9dc568bede01f24413fd70b77b02b414dde12f5e9ef04c7248241596e4dec6"

  strings:
    $s1  = "function aaEjdppQ(zniZN) {var YwBRcQNk=WqCptVySpxSw[2];for(var CBDPe=0;CBDPe<zniZN;CBDPe++){ongOo+=YwBRcQNk.charAt(Math.floor(Ma" ascii
    $s2  = "function aaEjdppQ(zniZN) {var YwBRcQNk=WqCptVySpxSw[2];for(var CBDPe=0;CBDPe<zniZN;CBDPe++){ongOo+=YwBRcQNk.charAt(Math.floor(Ma" ascii
    $s3  = "lzj.length;ZFFyPNFx++) {QMDNiBH+=UAgEf[analzj[ZFFyPNFx]];}return QMDNiBH.substring(3,QMDNiBH.length);}" fullword ascii
    $s4  = "function lIdCvVH() {var OvIB=100000;var oDtOqK = 100;return Math.random()*(OvIB-oDtOqK)+oDtOqK;}" fullword ascii
    $s5  = "if (xiSkUuX==0) break;" fullword ascii
    $s6  = "function RGVaC(xBwgxQTc,KZkoP,OLpRupdvCo){xBwgxQTc.open();xBwgxQTc.type = 1;xBwgxQTc.write(KZkoP);xBwgxQTc.position = 0;xBwgxQTc" ascii
    $s7  = "th.random()*YwBRcQNk.length));}return ongOo;}" fullword ascii
    $s8  = "function RGVaC(xBwgxQTc,KZkoP,OLpRupdvCo){xBwgxQTc.open();xBwgxQTc.type = 1;xBwgxQTc.write(KZkoP);xBwgxQTc.position = 0;xBwgxQTc" ascii
    $s9  = "function ngNJuV(ZHlHSD){return ZHlHSD.ExpandEnvironmentStrings(WqCptVySpxSw[10])}" fullword ascii
    $s10 = "try{xiSkUuX=kpuyHEbEt(GZXiV[eXzY], lIdCvVH() + WqCptVySpxSw[9], 1)}catch(e){}; " fullword ascii
    $s11 = "function kpuyHEbEt(zsQheQcgq,NhgcgLS,GuSBSCiU){" fullword ascii
    $s12 = "function cGyz(kcTobP,YAyxzAZ){gHgE = WqCptVySpxSw[11].split(WqCptVySpxSw[12]);YAyxzAZ.open(gHgE[0]+gHgE[2]+gHgE[3], kcTobP, fals" ascii
    $s13 = "function cGyz(kcTobP,YAyxzAZ){gHgE = WqCptVySpxSw[11].split(WqCptVySpxSw[12]);YAyxzAZ.open(gHgE[0]+gHgE[2]+gHgE[3], kcTobP, fals" ascii
    $s14 = "function YJSbA(QWjwOtwc,analzj,HoJmBeDau){UAgEf=QWjwOtwc.split(HoJmBeDau);QMDNiBH = WqCptVySpxSw[13];for(ZFFyPNFx=0;ZFFyPNFx<ana" ascii
    $s15 = "function LIQbG(ZHlHSD){return new ActiveXObject(ZHlHSD);}" fullword ascii
    $s16 = "function YJSbA(QWjwOtwc,analzj,HoJmBeDau){UAgEf=QWjwOtwc.split(HoJmBeDau);QMDNiBH = WqCptVySpxSw[13];for(ZFFyPNFx=0;ZFFyPNFx<ana" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}