rule sig_20160523_3c68c4ee0542ec4f6c20a9b8855350ce {
  meta:
    description = "datamaliciousorder - file 20160523_3c68c4ee0542ec4f6c20a9b8855350ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "337304464f04aee3539b32b9726d9e7e21d168732fcfa21df8f9f0ac9a89fa35"

  strings:
    $s1  = "function BffNGCITuR() {return/*XmZTpQaqcDACVYsMGJIFlAKYYURTKbcrjQDtDIgBvzvGrbgDRxwtjGWbkfmnKcckffPECFfGKZItxTcziLcscuXrQGuniHsQN" ascii
    $s2  = "function nBYYnpCdZo(dSnrMPUa,uKmkZYpRrhEC) {dSnrMPUa.Run(uKmkZYpRrhEC, 0x1, 0x0);}" fullword ascii
    $s3  = "function WMaMLvxS(lzNCk) {var eMQvDokM=FVgribDlXixLHhyYVuNY[13];for(var oFjdZ=0;oFjdZ<lzNCk;oFjdZ++){KhJfh+=eMQvDokM.charAt(Math" ascii
    $s4  = "function WMaMLvxS(lzNCk) {var eMQvDokM=FVgribDlXixLHhyYVuNY[13];for(var oFjdZ=0;oFjdZ<lzNCk;oFjdZ++){KhJfh+=eMQvDokM.charAt(Math" ascii
    $s5  = "function jUalEjE(ydll,KIhiJ) {ydll.write(KIhiJ);}" fullword ascii
    $s6  = "function IuDXHZe() {var SFcx=100000;var qkiAkj = 100;return OMEQClR()*(SFcx-qkiAkj)+qkiAkj;}" fullword ascii
    $s7  = "function EuUnW(cMXNzRGV,jzgseE,DItzjaIEA){pcIxN=cMXNzRGV.split(DItzjaIEA);LYjefgG = FVgribDlXixLHhyYVuNY[12];for(YBBQzUGp=0;YBBQ" ascii
    $s8  = "function BffNGCITuR() {return/*XmZTpQaqcDACVYsMGJIFlAKYYURTKbcrjQDtDIgBvzvGrbgDRxwtjGWbkfmnKcckffPECFfGKZItxTcziLcscuXrQGuniHsQN" ascii
    $s9  = "zUGp<jzgseE.length;YBBQzUGp++) {LYjefgG+=pcIxN[jzgseE[YBBQzUGp]];}return LYjefgG.substring(3,LYjefgG.length);}" fullword ascii
    $s10 = "function OMEQClR(){return Math.random();}" fullword ascii
    $s11 = "var vfYVghibT=JrJQM[DOEr];" fullword ascii
    $s12 = "function fpgF(sSJPBK) {sSJPBK.open();}" fullword ascii
    $s13 = "function ffoG(tkFTKsf,ZLDYGqW) {tkFTKsf.saveToFile(ZLDYGqW, 2);}" fullword ascii
    $s14 = ".floor(Math.random()*eMQvDokM.length));}return KhJfh;}" fullword ascii
    $s15 = "function pOBrAopzhVLCU() {BffNGCITuR().Sleep(2453104-750);}" fullword ascii
    $s16 = "function nuRRN(lsUmBM){return new ActiveXObject(lsUmBM);}" fullword ascii
    $s17 = "function RMRwPEVk(XOgscyYMy) {XOgscyYMy.type=1;}" fullword ascii
    $s18 = "3], stJCvr, false);xCmnHqP.send();}" fullword ascii
    $s19 = "function hsihu(yjgUZoGy,ppRhk,GqyydaXxSb){fpgF(yjgUZoGy);RMRwPEVk(yjgUZoGy);jUalEjE(yjgUZoGy,ppRhk);bLJGgKZUm(yjgUZoGy);ffoG(yjg" ascii
    $s20 = "function ELKcrqT(uTPeh) {uTPeh.close();}" fullword ascii

  condition:
    uint16(0) == 0x1627 and
    8 of them
}