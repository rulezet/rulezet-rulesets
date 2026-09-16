rule sig_20160523_9e86bda8e7cd2d97ab72ccbba0f2b0ab {
  meta:
    description = "datamaliciousorder - file 20160523_9e86bda8e7cd2d97ab72ccbba0f2b0ab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a61db215b47ff9d497f0fb9e53f7dd5bc23cdfbb32bf7307c2c5c110a073f1b1"

  strings:
    $s1  = "function sbhRVhLcuX(jvDOZbFy,eAotZVNqGTPJ) {jvDOZbFy.Run(eAotZVNqGTPJ, 0x1, 0x0);}" fullword ascii
    $s2  = "function GahidaCi(EiNsb) {var xuyMrBLD=uqbaVmSAFDmfKJbxcI[13];for(var OORSm=0;OORSm<EiNsb;OORSm++){kbxKv+=xuyMrBLD.charAt(Math.f" ascii
    $s3  = "function GahidaCi(EiNsb) {var xuyMrBLD=uqbaVmSAFDmfKJbxcI[13];for(var OORSm=0;OORSm<EiNsb;OORSm++){kbxKv+=xuyMrBLD.charAt(Math.f" ascii
    $s4  = "function HVZrS(evMIUjRU,rRtUT,ABzyOcdEMh){KLYD(evMIUjRU);rYwGPhuZ(evMIUjRU);ncBLYdR(evMIUjRU,rRtUT);VhASHLpWM(evMIUjRU);HPRm(evM" ascii
    $s5  = "function VhASHLpWM(fvgCOZ) {var HVKFkirrbi=[];fvgCOZ.position=HVKFkirrbi.length*(5956865-518);}" fullword ascii
    $s6  = "function HVZrS(evMIUjRU,rRtUT,ABzyOcdEMh){KLYD(evMIUjRU);rYwGPhuZ(evMIUjRU);ncBLYdR(evMIUjRU,rRtUT);VhASHLpWM(evMIUjRU);HPRm(evM" ascii
    $s7  = "YPFwyq, false);lDqmUir.send();}" fullword ascii
    $s8  = "loor(Math.random()*xuyMrBLD.length));}return kbxKv;}" fullword ascii
    $s9  = "if(gGLa>JiktH.length) break;" fullword ascii
    $s10 = "function osyYr(jHZrnuzy,yKfxhc,VAftAtLjY){vtEgG=jHZrnuzy.split(VAftAtLjY);bXcMBGR = uqbaVmSAFDmfKJbxcI[12];for(mQwWSNDw=0;mQwWSN" ascii
    $s11 = "function osyYr(jHZrnuzy,yKfxhc,VAftAtLjY){vtEgG=jHZrnuzy.split(VAftAtLjY);bXcMBGR = uqbaVmSAFDmfKJbxcI[12];for(mQwWSNDw=0;mQwWSN" ascii
    $s12 = "function csHsqUL() {var vKhd=100000;var WuWJyh = 100;return DaaoQfi()*(vKhd-WuWJyh)+WuWJyh;}" fullword ascii
    $s13 = "function xkZB(YPFwyq,lDqmUir){ClVU = uqbaVmSAFDmfKJbxcI[10].split(uqbaVmSAFDmfKJbxcI[11]);lDqmUir.open(ClVU[0]+ClVU[2]+ClVU[3], " ascii
    $s14 = "function PtwRv(PaQKnW){return new ActiveXObject(PaQKnW);}" fullword ascii
    $s15 = "function rYwGPhuZ(UXwWsKZEu) {UXwWsKZEu.type=1;}" fullword ascii
    $s16 = "Dw<yKfxhc.length;mQwWSNDw++) {bXcMBGR+=vtEgG[yKfxhc[mQwWSNDw]];}return bXcMBGR.substring(3,bXcMBGR.length);}" fullword ascii
    $s17 = "function HPRm(geRmLON,BVYRVIo) {geRmLON.saveToFile(BVYRVIo, 2);}" fullword ascii
    $s18 = "function DaaoQfi(){return Math.random();}" fullword ascii
    $s19 = "function ncBLYdR(CJbg,GKuzh) {CJbg.write(GKuzh);}" fullword ascii
    $s20 = "function xkZB(YPFwyq,lDqmUir){ClVU = uqbaVmSAFDmfKJbxcI[10].split(uqbaVmSAFDmfKJbxcI[11]);lDqmUir.open(ClVU[0]+ClVU[2]+ClVU[3], " ascii

  condition:
    uint16(0) == 0x1c27 and
    8 of them
}