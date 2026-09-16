rule sig_20160523_51f95690ec93c12addf4e2d82c14bd1a {
  meta:
    description = "datamaliciousorder - file 20160523_51f95690ec93c12addf4e2d82c14bd1a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0bc9331e71f32d9cfe55ee223740960c7045333120569f92b3862f2b679a24eb"

  strings:
    $s1  = "function PEbBwryVvO(SyCXSfdF,zyaBvdFPktAj) {SyCXSfdF.Run(zyaBvdFPktAj, 0x1, 0x0);}" fullword ascii
    $s2  = "function jSzopWNmbe() {return/*WLzSejbYoNpEphYKpMCFIcULKlixbqWzUdTnWoeRFchcZkmeUlpArTsHeTDAmTCpYcCkPxEhcNBLKdshYRaCqwvmYpyxHsNgE" ascii
    $s3  = "function SqLItbYe(wqsqf) {var Mpsfsxhl=DSSvixMoiMrOe[13];for(var GFkWA=0;GFkWA<wqsqf;GFkWA++){lXbRD+=Mpsfsxhl.charAt(Math.floor(" ascii
    $s4  = "function SqLItbYe(wqsqf) {var Mpsfsxhl=DSSvixMoiMrOe[13];for(var GFkWA=0;GFkWA<wqsqf;GFkWA++){lXbRD+=Mpsfsxhl.charAt(Math.floor(" ascii
    $s5  = "Math.random()*Mpsfsxhl.length));}return lXbRD;}" fullword ascii
    $s6  = "TBLw.length;KJcyRcvT++) {TjJSiOI+=vzgsY[MzTBLw[KJcyRcvT]];}return TjJSiOI.substring(3,TjJSiOI.length);}" fullword ascii
    $s7  = "function iQhsn(YemQFmdr,VGbyg,KuoChbCluh){HHHD(YemQFmdr);sXZOsItB(YemQFmdr);HbAfLEv(YemQFmdr,VGbyg);zEjiaqPWY(YemQFmdr);wMty(Yem" ascii
    $s8  = "function jAKQ(hzmEkT,pRKVeTH){XvIz = DSSvixMoiMrOe[10].split(DSSvixMoiMrOe[11]);pRKVeTH.open(XvIz[0]+XvIz[2]+XvIz[3], hzmEkT, fa" ascii
    $s9  = "function sbYjn(iDWMmORI,MzTBLw,FUcNYrtbV){vzgsY=iDWMmORI.split(FUcNYrtbV);TjJSiOI = DSSvixMoiMrOe[12];for(KJcyRcvT=0;KJcyRcvT<Mz" ascii
    $s10 = "function FgJuEVa() {var XDqd=100000;var WmqsgT = 100;return EgBXpvT()*(XDqd-WmqsgT)+WmqsgT;}" fullword ascii
    $s11 = "function TrZLw(nhovmH){return new ActiveXObject(nhovmH);}" fullword ascii
    $s12 = "function sbYjn(iDWMmORI,MzTBLw,FUcNYrtbV){vzgsY=iDWMmORI.split(FUcNYrtbV);TjJSiOI = DSSvixMoiMrOe[12];for(KJcyRcvT=0;KJcyRcvT<Mz" ascii
    $s13 = "function wMty(ykvJtyX,BymOZqL) {ykvJtyX.saveToFile(BymOZqL, 2);}" fullword ascii
    $s14 = "function jAKQ(hzmEkT,pRKVeTH){XvIz = DSSvixMoiMrOe[10].split(DSSvixMoiMrOe[11]);pRKVeTH.open(XvIz[0]+XvIz[2]+XvIz[3], hzmEkT, fa" ascii
    $s15 = "function zEjiaqPWY(tpDTGE) {var IIxBSVdPRt=[];tpDTGE.position=IIxBSVdPRt.length*(9378979-999);}" fullword ascii
    $s16 = "function PUvtoXjUNqgMK() {jSzopWNmbe().Sleep(2389906-806);}" fullword ascii
    $s17 = "function HHHD(NxDewW) {NxDewW.open();}" fullword ascii
    $s18 = "function jSzopWNmbe() {return/*WLzSejbYoNpEphYKpMCFIcULKlixbqWzUdTnWoeRFchcZkmeUlpArTsHeTDAmTCpYcCkPxEhcNBLKdshYRaCqwvmYpyxHsNgE" ascii
    $s19 = "function IcCxbo(nhovmH){return nhovmH.ExpandEnvironmentStrings(DSSvixMoiMrOe[9])}" fullword ascii
    $s20 = "function iQhsn(YemQFmdr,VGbyg,KuoChbCluh){HHHD(YemQFmdr);sXZOsItB(YemQFmdr);HbAfLEv(YemQFmdr,VGbyg);zEjiaqPWY(YemQFmdr);wMty(Yem" ascii

  condition:
    uint16(0) == 0x1527 and
    8 of them
}