rule sig_20151217_d66f838d7be3ee440784a4bc7daeb142 {
  meta:
    description = "datamaliciousorder - file 20151217_d66f838d7be3ee440784a4bc7daeb142.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fdd21c3f666fcf76b59d8280bca4ae50345f806fed430cd31ed175d5e13aeb2c"

  strings:
    $s1  = "(Math.cos(779), 2) - 1)));} NPEbyQsoB[VBFBFIIsDQC]++;}VBFBFIIsDQC++;} return QtFaWhxiVvW}" fullword ascii
    $s2  = "function TDDsqREPpqdXcGZXj(tcMAu){QtFaWhxiVvW= '';VBFBFIIsDQC=Math.round((Math.pow(Math.sin(18), 2) + Math.pow(Math.cos(18), 2) " ascii
    $s3  = ".pow(Math.cos(217), 2) - 1)); while(true) { if(NPEbyQsoB[VBFBFIIsDQC] > tcMAu[VBFBFIIsDQC].length-(-411+670)/259) { break; } if " ascii
    $s4  = "- 1));while(true){if (VBFBFIIsDQC >= (3203+343)/591){break;}NPEbyQsoB[VBFBFIIsDQC]=Math.round((Math.pow(Math.sin(217), 2) + Math" ascii
    $s5  = "function TDDsqREPpqdXcGZXj(tcMAu){QtFaWhxiVvW= '';VBFBFIIsDQC=Math.round((Math.pow(Math.sin(18), 2) + Math.pow(Math.cos(18), 2) " ascii
    $s6  = "function vbQDNlMRXHbbmwY(epprPvpXmIcudRbxx,KMDYpqpsMTZJBSaGBinlPuKXoJXvbAqFGb,MFmDdcMudquIuHAOAiJjSAhOUaZQJPgsxGl){eval(epprPvpX" ascii
    $s7  = "function OoVkMgK(NfnHrLntwsdsiBgywPlRSALsEmcqJvMLSTpd) {return !oVWbldVeZzI(mMWCVdIXMvWPEcn(NfnHrLntwsdsiBgywPlRSALsEmcqJvMLSTpd" ascii
    $s8  = "function vbQDNlMRXHbbmwY(epprPvpXmIcudRbxx,KMDYpqpsMTZJBSaGBinlPuKXoJXvbAqFGb,MFmDdcMudquIuHAOAiJjSAhOUaZQJPgsxGl){eval(epprPvpX" ascii
    $s9  = "var N = new Array();N[0]=[];N[0][0]='d';N[0][1]='a';N[0][2]='d';N[0][3]='a';N[0][4]='46';N[0][5]='3d';N[0][6]='42';N[0][7]='14';" ascii
    $s10 = "function oVWbldVeZzI(cnMBlmSxWsTRlF) {return isNaN(cnMBlmSxWsTRlF);}" fullword ascii
    $s11 = "function thYBGQdpLmXIkJjkz(JJcVyPQGTO,SGYDrInPcE) {return parseInt(JJcVyPQGTO,SGYDrInPcE);}" fullword ascii
    $s12 = "function cnoBZmxxcRTgTQCqBkgeCMVlJzcLfHTbupYmgzNbOSHXbyaoFCojqd(gZOfsVfGoufWZ,olsEHnplXHpsQo){ return FvvZnMo[hWaFhtjo[jPwjS(gZO" ascii
    $s13 = "function cnoBZmxxcRTgTQCqBkgeCMVlJzcLfHTbupYmgzNbOSHXbyaoFCojqd(gZOfsVfGoufWZ,olsEHnplXHpsQo){ return FvvZnMo[hWaFhtjo[jPwjS(gZO" ascii
    $s14 = "P);return WdoQt;}" fullword ascii
    $s15 = "function o(dZhnbgbtPclJ,uHUzCiRPmKqDlU){dZhnbgbtPclJ.push(uHUzCiRPmKqDlU);}" fullword ascii
    $s16 = "function jPwjS(tWZHUqaOKBH,oTcquFHIXVEYV,DidwRXsP){ehRo=thYBGQdpLmXIkJjkz(tWZHUqaOKBH,oTcquFHIXVEYV);WdoQt=ehRo.toString(DidwRXs" ascii
    $s17 = "function jPwjS(tWZHUqaOKBH,oTcquFHIXVEYV,DidwRXsP){ehRo=thYBGQdpLmXIkJjkz(tWZHUqaOKBH,oTcquFHIXVEYV);WdoQt=ehRo.toString(DidwRXs" ascii
    $s18 = "function YnJPpVFHjhzY(mbXBLnTqsAmHf) {return isFinite(mbXBLnTqsAmHf);}" fullword ascii
    $s19 = "function OoVkMgK(NfnHrLntwsdsiBgywPlRSALsEmcqJvMLSTpd) {return !oVWbldVeZzI(mMWCVdIXMvWPEcn(NfnHrLntwsdsiBgywPlRSALsEmcqJvMLSTpd" ascii
    $s20 = "function mMWCVdIXMvWPEcn(QRBJEwEZzPZwxKnJSXU) {return parseFloat(QRBJEwEZzPZwxKnJSXU);}" fullword ascii

  condition:
    uint16(0) == 0x5768 and
    8 of them
}