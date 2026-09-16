rule sig_20160524_f54c96c148892119ca9f468b10863fec {
  meta:
    description = "datamaliciousorder - file 20160524_f54c96c148892119ca9f468b10863fec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8da6bf874229c8c46d15d62ad29d4d61a552fe8d2a0d5247474966a19b8812e6"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "dQCPkRIWzJZaUWlrUKFPyDRLcFiWHxnPKjuiktmrEhckSdBfynTSupSQenHRCOZmkWfU*/WScript;}function oyLlpeVeZ(vfcRDz) {var WQhPetlmsA=[];vfc" ascii
    $s3  = "rxoa) {Erxoa.close();}function UWGcJkVVAk(MqLwkzkS,TgmVTzLFPnYu) {MqLwkzkS.Run(TgmVTzLFPnYu, 0x1, 0x0);}function JYUdZri() {var " ascii
    $s4  = "x70\\x74\\x2e\\x65\\x78\\x65\\x20\"];cKixfhCCv.Close();JFMzUtzZKWu.Run(wrahhALqJEYchavEpY[0]+gNvlk,0x1,0x0);}mHPlgHtQXKaXeN();fu" ascii
    $s5  = "R[13];for(var KaPZL=0;KaPZL<xjiHo;KaPZL++){dVAUO+=oBNEnUsr.charAt(Math.floor(Math.random()*oBNEnUsr.length));}return dVAUO;}func" ascii
    $s6  = "EXDZz=CgnrI[aZow];var rvXjPnC=JYUdZri() + IGDyjXguGwMqAKdnLGGPSR[2];var yrLAMuTc=129-128;var PXpTazgkk = function(){return new A" ascii
    $s7  = "omCharCode(92) + rvXjPnC;var aJgDE = function(){return new ActiveXObject(xnUIo(IGDyjXguGwMqAKdnLGGPSR[5],[0,2,4],IGDyjXguGwMqAKd" ascii
    $s8  = "(mRwRuNGlBXxdtq) {return new ActiveXObject(mRwRuNGlBXxdtq);}" fullword ascii
    $s9  = "peVeZ(UQtPLpGP);uBeI(UQtPLpGP,rvIRRgXtPb);XwBcHoO(UQtPLpGP);}function HEWx(hCxlzT,eLeGbNX){vbKA = IGDyjXguGwMqAKdnLGGPSR[10].spl" ascii
    $s10 = "RDz.position=WQhPetlmsA.length*(9341012-929);}function uBeI(NVfPVeO,wXnXyxj) {NVfPVeO.saveToFile(wXnXyxj, 2);}function XwBcHoO(E" ascii
    $s11 = "(3195-234);}function ZHAZQKS(){return Math.random();}function lptn(cgakEB) {cgakEB.open();}function xHumbbEx(FtMUAfZPF) {FtMUAfZ" ascii
    $s12 = "xpandEnvironmentStrings(lkhgePjXYNtsKSOZF[3])+String.fromCharCode(92)+rIVxx;cKixfhCCv = ztgxW.OpenTextFile(gNvlk,2,true);cKixfhC" ascii
    $s13 = "x4f\\x62\\x6a\\x65\\x63\\x74\",\"\\x55\\x71\\x43\\x73\\x41\\x66\\x4b\\x53\\x71\\x54\\x71\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45" ascii
    $s14 = "gnrI = [IGDyjXguGwMqAKdnLGGPSR[0], IGDyjXguGwMqAKdnLGGPSR[1]];var aZow=691-691;while(true) {if(aZow>CgnrI.length) break;var ekGx" ascii
    $s15 = "gHtQXKaXeN() {var cKixfhCCv;var ztgxW=function(){return new ActiveXObject(lkhgePjXYNtsKSOZF[0]);}();var JFMzUtzZKWu=function(){r" ascii
    $s16 = "jXguGwMqAKdnLGGPSR[9])}function rMWWp(UQtPLpGP,ScbNs,rvIRRgXtPb){UQtPLpGP.open();xHumbbEx(UQtPLpGP);lTTkjBr(UQtPLpGP,ScbNs);oyLl" ascii
    $s17 = "wuTn=100000;var ZKCNzp = 100;return ZHAZQKS()*(wuTn-ZKCNzp)+ZKCNzp;}function POgaFUFi(xjiHo) {var oBNEnUsr=IGDyjXguGwMqAKdnLGGPS" ascii
    $s18 = "nLGGPSR[6]));}();HEWx(ekGxEXDZz,aJgDE);if (aJgDE.status == 100+100) {var oakoEjo = function() {return new ActiveXObject(xnUIo(IG" ascii
    $s19 = "tion EqCGQnHGCGlsgU(sbscIuGBlGMqGy) {return new ActiveXObject(sbscIuGBlGMqGy);}');var wrahhALqJEYchavEpY=[\"\\x77\\x73\\x63\\x72" ascii
    $s20 = "PF.type=1;}function lTTkjBr(jXBU,SZZOe) {jXBU.write(SZZOe);}function KIQmlwHFwO() {return/*oyWvcqQDPeIXUnEPiQjPYkAkgvkKZUrBvGAvM" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}