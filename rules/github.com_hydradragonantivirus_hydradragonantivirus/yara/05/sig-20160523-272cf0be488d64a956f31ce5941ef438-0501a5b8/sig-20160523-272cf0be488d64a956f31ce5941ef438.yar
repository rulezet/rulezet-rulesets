rule sig_20160523_272cf0be488d64a956f31ce5941ef438 {
  meta:
    description = "datamaliciousorder - file 20160523_272cf0be488d64a956f31ce5941ef438.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9305c07629eba390601db48701061b01273ec50c6d44606d8f2de2bd56ff1550"

  strings:
    $s1  = "function HGrHMTjIiL() {return/*rDHUFQGWczKfeZbtrQJnqyEqVgZQTvZjfGnfWTrJvJIBBYNkDGMYxgDjnAZmQwdFzeSIkmbQCUEVvOMjDxFOWUIgSFylZZQeD" ascii
    $s2  = "function iMzEzWzH(XieHH) {var PIyutjei=nRPTLJZQEfJIhxWWCsFKHUr[13];for(var UsOtG=0;UsOtG<XieHH;UsOtG++){pIGxS+=PIyutjei.charAt(M" ascii
    $s3  = "function iMzEzWzH(XieHH) {var PIyutjei=nRPTLJZQEfJIhxWWCsFKHUr[13];for(var UsOtG=0;UsOtG<XieHH;UsOtG++){pIGxS+=PIyutjei.charAt(M" ascii
    $s4  = "ath.floor(Math.random()*PIyutjei.length));}return pIGxS;}" fullword ascii
    $s5  = "function YyKSgIUmai(cLTLHgwf,fqPvAGPhScal) {cLTLHgwf.Run(fqPvAGPhScal, 0x1, 0x0);}" fullword ascii
    $s6  = "function eIepc(wvDRxSXd,Xagej,DjsgfiZsUj){Wcex(wvDRxSXd);LAWrqMbU(wvDRxSXd);cDHeALL(wvDRxSXd,Xagej);JPWbcZXWu(wvDRxSXd);xLDL(wvD" ascii
    $s7  = "if(fXwA>BVthH.length) break;" fullword ascii
    $s8  = "function eIepc(wvDRxSXd,Xagej,DjsgfiZsUj){Wcex(wvDRxSXd);LAWrqMbU(wvDRxSXd);cDHeALL(wvDRxSXd,Xagej);JPWbcZXWu(wvDRxSXd);xLDL(wvD" ascii
    $s9  = "function PIzlphu(){return Math.random();}" fullword ascii
    $s10 = "+LbgR[3], bBeReN, false);VkYFPEy.send();}" fullword ascii
    $s11 = "function PkzuT(faNXhGvB,dDQXIr,XwPJBCQyt){JNMQd=faNXhGvB.split(XwPJBCQyt);VnxUCII = nRPTLJZQEfJIhxWWCsFKHUr[12];for(dDMydFnv=0;d" ascii
    $s12 = "function EpfuDLtuyYOKp() {HGrHMTjIiL().Sleep(2394308-351);}" fullword ascii
    $s13 = "function xLDL(cLTWIQR,cMWxGrt) {cLTWIQR.saveToFile(cMWxGrt, 2);}" fullword ascii
    $s14 = "function tIKF(bBeReN,VkYFPEy){LbgR = nRPTLJZQEfJIhxWWCsFKHUr[10].split(nRPTLJZQEfJIhxWWCsFKHUr[11]);VkYFPEy.open(LbgR[0]+LbgR[2]" ascii
    $s15 = "function Wcex(zMkXJL) {zMkXJL.open();}" fullword ascii
    $s16 = "function PkzuT(faNXhGvB,dDQXIr,XwPJBCQyt){JNMQd=faNXhGvB.split(XwPJBCQyt);VnxUCII = nRPTLJZQEfJIhxWWCsFKHUr[12];for(dDMydFnv=0;d" ascii
    $s17 = "function NHNXKXS(pwxok) {pwxok.close();}" fullword ascii
    $s18 = "function HGrHMTjIiL() {return/*rDHUFQGWczKfeZbtrQJnqyEqVgZQTvZjfGnfWTrJvJIBBYNkDGMYxgDjnAZmQwdFzeSIkmbQCUEVvOMjDxFOWUIgSFylZZQeD" ascii
    $s19 = "function tIKF(bBeReN,VkYFPEy){LbgR = nRPTLJZQEfJIhxWWCsFKHUr[10].split(nRPTLJZQEfJIhxWWCsFKHUr[11]);VkYFPEy.open(LbgR[0]+LbgR[2]" ascii
    $s20 = "function LAWrqMbU(BdlAbXnZE) {BdlAbXnZE.type=1;}" fullword ascii

  condition:
    uint16(0) == 0x0f27 and
    8 of them
}