rule sig_20160523_f294789934e76d7aae8d4cae548ee7cb {
  meta:
    description = "datamaliciousorder - file 20160523_f294789934e76d7aae8d4cae548ee7cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8bde7c9e4f003a134d7e69b7ac10048513f075fb9ba905080366dbc82c231427"

  strings:
    $s1  = "function JFUBqYhRZQ() {return/*YOswLdPWrMMrWsJBkcIrsNbVfzFNBHTMuCBnydMYQCDoqNVOswDklJyRXiUZioLuFRrxepEQwldqbqoWVfVHzQWRomygLRvwY" ascii
    $s2  = "function ZaGNpHziBQ(PTcwWRus,LPJvrGTBpFen) {PTcwWRus.Run(LPJvrGTBpFen, 0x1, 0x0);}" fullword ascii
    $s3  = "function MbQTzrkH(aBCcB) {var TJxKzAdZ=yTvCMP[13];for(var szmps=0;szmps<aBCcB;szmps++){EjwkH+=TJxKzAdZ.charAt(Math.floor(Math.ra" ascii
    $s4  = "function MbQTzrkH(aBCcB) {var TJxKzAdZ=yTvCMP[13];for(var szmps=0;szmps<aBCcB;szmps++){EjwkH+=TJxKzAdZ.charAt(Math.floor(Math.ra" ascii
    $s5  = "function hSIeBXF() {var jkYw=100000;var FxeChv = 100;return jlwUmAV()*(jkYw-FxeChv)+FxeChv;}" fullword ascii
    $s6  = "function OUtM(dyLpFdH,pHWUqxH) {dyLpFdH.saveToFile(pHWUqxH, 2);}" fullword ascii
    $s7  = "function jMBY(stvwUG,TWhJpcw){JiVe = yTvCMP[10].split(yTvCMP[11]);TWhJpcw.open(JiVe[0]+JiVe[2]+JiVe[3], stvwUG, false);TWhJpcw.s" ascii
    $s8  = "function VCFxD(vEDxTgsT,HNkXRw,rAQFVUKlW){ipogT=vEDxTgsT.split(rAQFVUKlW);hzDBNhZ = yTvCMP[12];for(vvypconr=0;vvypconr<HNkXRw.le" ascii
    $s9  = "ngth;vvypconr++) {hzDBNhZ+=ipogT[HNkXRw[vvypconr]];}return hzDBNhZ.substring(3,hzDBNhZ.length);}" fullword ascii
    $s10 = "if(yLrS>NHEJJ.length) break;" fullword ascii
    $s11 = "function QPicnZc(wpWR,MMIEP) {wpWR.write(MMIEP);}" fullword ascii
    $s12 = "function mXddq(zKHjSzAx,bsGrt,RclVLjfmmn){oIOG(zKHjSzAx);BshcNpmH(zKHjSzAx);QPicnZc(zKHjSzAx,bsGrt);rojPFMJrX(zKHjSzAx);OUtM(zKH" ascii
    $s13 = "function GUPqFoLbWvQbR() {JFUBqYhRZQ().Sleep(2418889-574);}" fullword ascii
    $s14 = "function vkVKpRp(iGrMF) {iGrMF.close();}" fullword ascii
    $s15 = "function jMBY(stvwUG,TWhJpcw){JiVe = yTvCMP[10].split(yTvCMP[11]);TWhJpcw.open(JiVe[0]+JiVe[2]+JiVe[3], stvwUG, false);TWhJpcw.s" ascii
    $s16 = "function gGeyBS(YRmcbG){return YRmcbG.ExpandEnvironmentStrings(yTvCMP[9])}" fullword ascii
    $s17 = "function jlwUmAV(){return Math.random();}" fullword ascii
    $s18 = "function oIOG(XLQfCz) {XLQfCz.open();}" fullword ascii
    $s19 = "function rojPFMJrX(HzYRNB) {var UrrRjbTMFe=[];HzYRNB.position=UrrRjbTMFe.length*(2485013-945);}" fullword ascii
    $s20 = "ndom()*TJxKzAdZ.length));}return EjwkH;}" fullword ascii

  condition:
    uint16(0) == 0x1427 and
    8 of them
}