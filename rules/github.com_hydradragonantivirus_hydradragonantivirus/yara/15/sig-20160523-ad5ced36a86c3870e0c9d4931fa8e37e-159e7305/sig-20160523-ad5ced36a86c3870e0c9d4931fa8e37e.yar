rule sig_20160523_ad5ced36a86c3870e0c9d4931fa8e37e {
  meta:
    description = "datamaliciousorder - file 20160523_ad5ced36a86c3870e0c9d4931fa8e37e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "64105d524d6e3cd25bd6972687de8b739e227d14b26f61b2fb4b2c891a7ee1df"

  strings:
    $s1  = "function JjaIarXG(rvSQZ) {var VRyROzpj=AiOpTd[2];for(var yUzVZ=0;yUzVZ<rvSQZ;yUzVZ++){HQrOR+=VRyROzpj.charAt(Math.floor(Math.ran" ascii
    $s2  = "function kMVGXWJOKj(EMHuGgAS,naAwwatyIjqQ) {EMHuGgAS.Run(naAwwatyIjqQ, 0x1, 0x0);}" fullword ascii
    $s3  = "function JjaIarXG(rvSQZ) {var VRyROzpj=AiOpTd[2];for(var yUzVZ=0;yUzVZ<rvSQZ;yUzVZ++){HQrOR+=VRyROzpj.charAt(Math.floor(Math.ran" ascii
    $s4  = "function ikdJO(ZCCUmziR,uaLxv,JWeNFcEwuO){bFTP(ZCCUmziR);llCFLaZY(ZCCUmziR);wPyduww(ZCCUmziR,uaLxv);zaXhfrZCy(ZCCUmziR);iGZW(ZCC" ascii
    $s5  = "function bFTP(oNJeXv) {oNJeXv.open();}" fullword ascii
    $s6  = "function ikdJO(ZCCUmziR,uaLxv,JWeNFcEwuO){bFTP(ZCCUmziR);llCFLaZY(ZCCUmziR);wPyduww(ZCCUmziR,uaLxv);zaXhfrZCy(ZCCUmziR);iGZW(ZCC" ascii
    $s7  = "dom()*VRyROzpj.length));}return HQrOR;}" fullword ascii
    $s8  = "function RdRnrdZ(){return Math.random();}" fullword ascii
    $s9  = "function LBnXE(voBImx){return new ActiveXObject(voBImx);}" fullword ascii
    $s10 = "function ITdFmJi() {var Eyfq=100000;var iczawk = 100;return RdRnrdZ()*(Eyfq-iczawk)+iczawk;}" fullword ascii
    $s11 = "function pUgq(deuvlA,ooGfuFF){sRHb = AiOpTd[11].split(AiOpTd[12]);ooGfuFF.open(sRHb[0]+sRHb[2]+sRHb[3], deuvlA, false);ooGfuFF.s" ascii
    $s12 = "function llCFLaZY(TRPEWBVdE) {TRPEWBVdE.type=1;}" fullword ascii
    $s13 = "function pUgq(deuvlA,ooGfuFF){sRHb = AiOpTd[11].split(AiOpTd[12]);ooGfuFF.open(sRHb[0]+sRHb[2]+sRHb[3], deuvlA, false);ooGfuFF.s" ascii
    $s14 = "function zaXhfrZCy(MbExkI) {var YvkaXiKGkc=[];MbExkI.position=YvkaXiKGkc.length*(1564576-516);}" fullword ascii
    $s15 = "try{BHwiisN=hkEweRbBb(DzRdG[QLti], ITdFmJi() + AiOpTd[9], 1)}catch(e){}; " fullword ascii
    $s16 = "function TMSKW(OlcyZXdi,LBSmQW,ZwGECXYAi){hpWHh=OlcyZXdi.split(ZwGECXYAi);qBreELB = AiOpTd[13];for(AlhUrlys=0;AlhUrlys<LBSmQW.le" ascii
    $s17 = "if (BHwiisN==0) break;" fullword ascii
    $s18 = "ngth;AlhUrlys++) {qBreELB+=hpWHh[LBSmQW[AlhUrlys]];}return qBreELB.substring(3,qBreELB.length);}" fullword ascii
    $s19 = "function CHrkcO(voBImx){return voBImx.ExpandEnvironmentStrings(AiOpTd[10])}" fullword ascii
    $s20 = "function fNuHmNz(VKpSk) {VKpSk.close();}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}