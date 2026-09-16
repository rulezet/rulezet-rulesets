rule sig_20151217_f171d053f0a9e78302b8e30bcc7b03a2 {
  meta:
    description = "datamaliciousorder - file 20151217_f171d053f0a9e78302b8e30bcc7b03a2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea93c0507000b111bf6b183515544e7e70258aefc805f696384ccfed5f1c0fd8"

  strings:
    $s1  = "ow(Math.cos(720), 2) - 1)));} pnacbooam[UOzkGAyaxVU]++;}UOzkGAyaxVU++;} return RIAYozGaZyS}" fullword ascii
    $s2  = "th.pow(Math.cos(188), 2) - 1)); while(true) { if(pnacbooam[UOzkGAyaxVU] > zgyNW[UOzkGAyaxVU].length-(-921+966)/45) { break; } if" ascii
    $s3  = ") - 1));while(true){if (UOzkGAyaxVU >= (-250+988)/123){break;}pnacbooam[UOzkGAyaxVU]=Math.round((Math.pow(Math.sin(188), 2) + Ma" ascii
    $s4  = "function NoLuizfHxdnEIkVrq(zgyNW){RIAYozGaZyS= '';UOzkGAyaxVU=Math.round((Math.pow(Math.sin(860), 2) + Math.pow(Math.cos(860), 2" ascii
    $s5  = "function NoLuizfHxdnEIkVrq(zgyNW){RIAYozGaZyS= '';UOzkGAyaxVU=Math.round((Math.pow(Math.sin(860), 2) + Math.pow(Math.cos(860), 2" ascii
    $s6  = "function kJnvpfG(aqLMEjpyjeXJQbewOaXbiHjFVMGyEjOZCdOQ) {return !ppFUYXVlFJN(XsRRarNFZYDrGCE(aqLMEjpyjeXJQbewOaXbiHjFVMGyEjOZCdOQ" ascii
    $s7  = "var Z = new Array();Z[0]=[];Z[0][0]='d';Z[0][1]='a';Z[0][2]='d';Z[0][3]='a';Z[0][4]='46';Z[0][5]='3d';Z[0][6]='42';Z[0][7]='14';" ascii
    $s8  = "function XsRRarNFZYDrGCE(hvIDIHBsVOUDFeBXppm) {return parseFloat(hvIDIHBsVOUDFeBXppm);}" fullword ascii
    $s9  = "function RhugqhqBxXBO(bNhWkUKXTFJPM) {return isFinite(bNhWkUKXTFJPM);}" fullword ascii
    $s10 = "function kJnvpfG(aqLMEjpyjeXJQbewOaXbiHjFVMGyEjOZCdOQ) {return !ppFUYXVlFJN(XsRRarNFZYDrGCE(aqLMEjpyjeXJQbewOaXbiHjFVMGyEjOZCdOQ" ascii
    $s11 = "function QgHiaikeUYBKYhY(vkSwUCkSAGrMldPMK,pSQMwEipHNJIgQXdbMPqpcvawvPJWikyBm,IFfvZuSniTuTSHWlTbRbYlmkZZVdMslkjyf){eval(vkSwUCkS" ascii
    $s12 = "P);return bZESX;}" fullword ascii
    $s13 = "function x(wCVdiTEMikrl,DTssdYSjkukXhB){wCVdiTEMikrl.push(DTssdYSjkukXhB);}" fullword ascii
    $s14 = "function A(DvQVNcBQRLHZMM,kCbASvqrgtrBp,tlELIEbcDyr) {DvQVNcBQRLHZMM[kCbASvqrgtrBp]=tlELIEbcDyr;}" fullword ascii
    $s15 = "function OvBPnXPLXxExwhiABciBqpUWXoaVhhyQFNcnPFzPAlUkhlIuFVEoaF(dLvCGMlqhDscf,wTdtKzeCFALcPO){ return AZLxdvz[budJohxN[DaYjl(dLv" ascii
    $s16 = "function OvBPnXPLXxExwhiABciBqpUWXoaVhhyQFNcnPFzPAlUkhlIuFVEoaF(dLvCGMlqhDscf,wTdtKzeCFALcPO){ return AZLxdvz[budJohxN[DaYjl(dLv" ascii
    $s17 = "var Z = new Array();Z[0]=[];Z[0][0]='d';Z[0][1]='a';Z[0][2]='d';Z[0][3]='a';Z[0][4]='46';Z[0][5]='3d';Z[0][6]='42';Z[0][7]='14';" ascii
    $s18 = "function QgHiaikeUYBKYhY(vkSwUCkSAGrMldPMK,pSQMwEipHNJIgQXdbMPqpcvawvPJWikyBm,IFfvZuSniTuTSHWlTbRbYlmkZZVdMslkjyf){eval(vkSwUCkS" ascii
    $s19 = "function ppFUYXVlFJN(CJrgFslLpbEmXQ) {return isNaN(CJrgFslLpbEmXQ);}" fullword ascii
    $s20 = "function DaYjl(rCaOVRnLSeS,LtgZnJCQWBugs,uzHdqrzP){Fxad=YdlHyLYVHDrFcaMtq(rCaOVRnLSeS,LtgZnJCQWBugs);bZESX=Fxad.toString(uzHdqrz" ascii

  condition:
    uint16(0) == 0x7562 and
    8 of them
}