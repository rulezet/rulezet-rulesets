rule sig_20160523_816eb7048e206c0fa0e578c17beed5eb {
  meta:
    description = "datamaliciousorder - file 20160523_816eb7048e206c0fa0e578c17beed5eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a2905ef8c163202365841ee2f34ff26ea011c7c7f1458d256eefab1c613b385"

  strings:
    $s1  = "function zMPrFMlLOa(xpifCltA,JMkBhSuqRkzt) {xpifCltA.Run(JMkBhSuqRkzt, 0x1, 0x0);}" fullword ascii
    $s2  = "function VDQRPpfK(pEGpK) {var atxtACsb=WinyBdOORyhGeFdrpcDWMfp[13];for(var JtEBo=0;JtEBo<pEGpK;JtEBo++){caIAI+=atxtACsb.charAt(M" ascii
    $s3  = "function VDQRPpfK(pEGpK) {var atxtACsb=WinyBdOORyhGeFdrpcDWMfp[13];for(var JtEBo=0;JtEBo<pEGpK;JtEBo++){caIAI+=atxtACsb.charAt(M" ascii
    $s4  = "function tKmu(QBVyML,URFdvyu){FXNc = WinyBdOORyhGeFdrpcDWMfp[10].split(WinyBdOORyhGeFdrpcDWMfp[11]);URFdvyu.open(FXNc[0]+FXNc[2]" ascii
    $s5  = "function Ahqcg(zaaPiWHh,aQtILz,CkJXDkXPs){QAHyw=zaaPiWHh.split(CkJXDkXPs);pDiAuFf = WinyBdOORyhGeFdrpcDWMfp[12];for(XkwlBwjx=0;X" ascii
    $s6  = "function tKmu(QBVyML,URFdvyu){FXNc = WinyBdOORyhGeFdrpcDWMfp[10].split(WinyBdOORyhGeFdrpcDWMfp[11]);URFdvyu.open(FXNc[0]+FXNc[2]" ascii
    $s7  = "function GsqTOd(qtsnxL){return qtsnxL.ExpandEnvironmentStrings(WinyBdOORyhGeFdrpcDWMfp[9])}" fullword ascii
    $s8  = "function Ahqcg(zaaPiWHh,aQtILz,CkJXDkXPs){QAHyw=zaaPiWHh.split(CkJXDkXPs);pDiAuFf = WinyBdOORyhGeFdrpcDWMfp[12];for(XkwlBwjx=0;X" ascii
    $s9  = "function wIIgrDTHcN() {return/*YqQMoBmWeZSrGaZCqiuEjIHtPeMoCAnJoOgUwfDwGBeSQEyBVFlUYbsogiLzWQOZCgDCGfXBKomeMESlYAchegUNPgkLIMjiB" ascii
    $s10 = "+FXNc[3], QBVyML, false);URFdvyu.send();}" fullword ascii
    $s11 = "function TzLA(aMKkGU) {aMKkGU.open();}" fullword ascii
    $s12 = "function DJogIwSiH(bYLxGx) {var UArMJqJzVN=[];bYLxGx.position=UArMJqJzVN.length*(6202004-449);}" fullword ascii
    $s13 = "function pJqkiQy(zmZf,napJS) {zmZf.write(napJS);}" fullword ascii
    $s14 = "kwlBwjx<aQtILz.length;XkwlBwjx++) {pDiAuFf+=QAHyw[aQtILz[XkwlBwjx]];}return pDiAuFf.substring(3,pDiAuFf.length);}" fullword ascii
    $s15 = "function ziUh(AiNyatA,uIxKnVS) {AiNyatA.saveToFile(uIxKnVS, 2);}" fullword ascii
    $s16 = "function PxVYYsS() {var Hbia=100000;var VBiaRU = 100;return efiTcfo()*(Hbia-VBiaRU)+VBiaRU;}" fullword ascii
    $s17 = "function iGIAg(qtsnxL){return new ActiveXObject(qtsnxL);}" fullword ascii
    $s18 = "function InoNhcjmYOSgu() {wIIgrDTHcN().Sleep(2335181-329);}" fullword ascii
    $s19 = "function efiTcfo(){return Math.random();}" fullword ascii
    $s20 = "function XFrXnAY(mgofP) {mgofP.close();}" fullword ascii

  condition:
    uint16(0) == 0x1c27 and
    8 of them
}