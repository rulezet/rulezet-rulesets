rule sig_20160523_83ce56c4dbfe5c032ff65ec4b5680238 {
  meta:
    description = "datamaliciousorder - file 20160523_83ce56c4dbfe5c032ff65ec4b5680238.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bfe22c3234ff4177fc577e3ce286f3c1ab55aad29d013a1825a909a2eac7c2a1"

  strings:
    $s1  = "function hxvDZYjusj(BblJiPdD,qCRvKHarCVDW) {BblJiPdD.Run(qCRvKHarCVDW, 0x1, 0x0);}" fullword ascii
    $s2  = "function HBPfehPo(ttamE) {var voWsaXSN=SravIIsNBHRhlTn[2];for(var tRXtk=0;tRXtk<ttamE;tRXtk++){rKqMm+=voWsaXSN.charAt(Math.floor" ascii
    $s3  = "function HBPfehPo(ttamE) {var voWsaXSN=SravIIsNBHRhlTn[2];for(var tRXtk=0;tRXtk<ttamE;tRXtk++){rKqMm+=voWsaXSN.charAt(Math.floor" ascii
    $s4  = "lFmtkq.length;FYcgaPTN++) {hZOOrks+=Xroku[lFmtkq[FYcgaPTN]];}return hZOOrks.substring(3,hZOOrks.length);}" fullword ascii
    $s5  = "function bboAraH() {var fexN=100000;var CMyQIn = 100;return nSMCsYG()*(fexN-CMyQIn)+CMyQIn;}" fullword ascii
    $s6  = "function NHJt(PwXIInX,zdyjXmX) {PwXIInX.saveToFile(zdyjXmX, 2);}" fullword ascii
    $s7  = "function lMFy(ffDFzF,HoYYkaH){vbLg = SravIIsNBHRhlTn[11].split(SravIIsNBHRhlTn[12]);HoYYkaH.open(vbLg[0]+vbLg[2]+vbLg[3], ffDFzF" ascii
    $s8  = "if (GPCKcGN==0) break;" fullword ascii
    $s9  = "function AISCIRBjK(aKlkWK) {var joPubBrekb=[];aKlkWK.position=joPubBrekb.length*(5907860-558);}" fullword ascii
    $s10 = "function MMBRblyY(cRIRMiSPE) {cRIRMiSPE.type=1;}" fullword ascii
    $s11 = "function qmJDUCR(gYZf,nhoRv) {gYZf.write(nhoRv);}" fullword ascii
    $s12 = "function OAfeiv(yctCFP){return yctCFP.ExpandEnvironmentStrings(SravIIsNBHRhlTn[10])}" fullword ascii
    $s13 = "function nSMCsYG(){return Math.random();}" fullword ascii
    $s14 = "function lKZpc(pVWFxtYv,lFmtkq,faBMunMDx){Xroku=pVWFxtYv.split(faBMunMDx);hZOOrks = SravIIsNBHRhlTn[13];for(FYcgaPTN=0;FYcgaPTN<" ascii
    $s15 = "function rJkUp(kYmGRyRt,OAKiO,xnfchBMpVW){GXWo(kYmGRyRt);MMBRblyY(kYmGRyRt);qmJDUCR(kYmGRyRt,OAKiO);AISCIRBjK(kYmGRyRt);NHJt(kYm" ascii
    $s16 = "try{GPCKcGN=Capleynzh(VkWVu[ezJJ], bboAraH() + SravIIsNBHRhlTn[9], 1)}catch(e){}; " fullword ascii
    $s17 = "function rJkUp(kYmGRyRt,OAKiO,xnfchBMpVW){GXWo(kYmGRyRt);MMBRblyY(kYmGRyRt);qmJDUCR(kYmGRyRt,OAKiO);AISCIRBjK(kYmGRyRt);NHJt(kYm" ascii
    $s18 = "function GXWo(eWKoHF) {eWKoHF.open();}" fullword ascii
    $s19 = "function cHDgC(yctCFP){return new ActiveXObject(yctCFP);}" fullword ascii
    $s20 = "function lMFy(ffDFzF,HoYYkaH){vbLg = SravIIsNBHRhlTn[11].split(SravIIsNBHRhlTn[12]);HoYYkaH.open(vbLg[0]+vbLg[2]+vbLg[3], ffDFzF" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}