rule sig_20160523_cf3995c1a3eb3444800ed653c08b59c1 {
  meta:
    description = "datamaliciousorder - file 20160523_cf3995c1a3eb3444800ed653c08b59c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "803d502301e319c953cb9839c397c3516c836d46e61fcf2cfb9c179852ce1878"

  strings:
    $s1  = "function ilZRFHhrpz(gOdrKSiZ,sLLHgjsUywcC) {gOdrKSiZ.Run(sLLHgjsUywcC, 0x1, 0x0);}" fullword ascii
    $s2  = "function juHPtymP(WAcBy) {var IPxwgpVR=wCSCrDERHLaqvlWtTnbKecc[13];for(var KQgzv=0;KQgzv<WAcBy;KQgzv++){rDXQa+=IPxwgpVR.charAt(M" ascii
    $s3  = "function juHPtymP(WAcBy) {var IPxwgpVR=wCSCrDERHLaqvlWtTnbKecc[13];for(var KQgzv=0;KQgzv<WAcBy;KQgzv++){rDXQa+=IPxwgpVR.charAt(M" ascii
    $s4  = "ath.floor(Math.random()*IPxwgpVR.length));}return rDXQa;}" fullword ascii
    $s5  = "function hrytUOZMSh() {return/*plNDhgxCaigkeXOtDOeQJvoYiZqiPgUlSnAWQciuprbWDcwxHMKNkkidyLKbkCvqWXDxHGxQZPtpuFtLPpVGITaigCldxDTrc" ascii
    $s6  = "function aKZy(eHLOpp,wMXSdGX){PRjI = wCSCrDERHLaqvlWtTnbKecc[10].split(wCSCrDERHLaqvlWtTnbKecc[11]);wMXSdGX.open(PRjI[0]+PRjI[2]" ascii
    $s7  = "+PRjI[3], eHLOpp, false);wMXSdGX.send();}" fullword ascii
    $s8  = "if(XRJY>EZYLW.length) break;" fullword ascii
    $s9  = "function Zaze(TjvigJc,bDcqUlP) {TjvigJc.saveToFile(bDcqUlP, 2);}" fullword ascii
    $s10 = "function PSoPyEQ(){return Math.random();}" fullword ascii
    $s11 = "function LarBU(iXeTyJPx,oTZhQO,rXNhVhjpF){djlrv=iXeTyJPx.split(rXNhVhjpF);hWFjcev = wCSCrDERHLaqvlWtTnbKecc[12];for(pvToJmcY=0;p" ascii
    $s12 = "function JfbExbaBs(YwOsYQ) {var jhFZjcwnEs=[];YwOsYQ.position=jhFZjcwnEs.length*(2808346-821);}" fullword ascii
    $s13 = "function KWAH(fxEVzl) {fxEVzl.open();}" fullword ascii
    $s14 = "function ruwIoWZ(SlyNQ) {SlyNQ.close();}" fullword ascii
    $s15 = "function mcxYXPE(DXcD,AiwmM) {DXcD.write(AiwmM);}" fullword ascii
    $s16 = "function LarBU(iXeTyJPx,oTZhQO,rXNhVhjpF){djlrv=iXeTyJPx.split(rXNhVhjpF);hWFjcev = wCSCrDERHLaqvlWtTnbKecc[12];for(pvToJmcY=0;p" ascii
    $s17 = "function aKZy(eHLOpp,wMXSdGX){PRjI = wCSCrDERHLaqvlWtTnbKecc[10].split(wCSCrDERHLaqvlWtTnbKecc[11]);wMXSdGX.open(PRjI[0]+PRjI[2]" ascii
    $s18 = "function pmoPikLQuhxkt() {hrytUOZMSh().Sleep(2331673-714);}" fullword ascii
    $s19 = "function Bfjjaa(sFhWMY){return sFhWMY.ExpandEnvironmentStrings(wCSCrDERHLaqvlWtTnbKecc[9])}" fullword ascii
    $s20 = "function BuuMbLV() {var QgMl=100000;var qastTi = 100;return PSoPyEQ()*(QgMl-qastTi)+qastTi;}" fullword ascii

  condition:
    uint16(0) == 0x1c27 and
    8 of them
}