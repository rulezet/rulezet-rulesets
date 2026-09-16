rule sig_20151217_921fdc36aad076e8415529174826642e {
  meta:
    description = "datamaliciousorder - file 20151217_921fdc36aad076e8415529174826642e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed84f633af3dfbb52477d38609d1baee359ddcf462b9eb88fbe970e693af9f42"

  strings:
    $s1  = "th.pow(Math.cos(686), 2) - 1)); while(true) { if(vNJwNncSj[WDjticwtuKx] > zTbud[WDjticwtuKx].length-(-65+773)/708) { break; } if" ascii
    $s2  = ") - 1));while(true){if (WDjticwtuKx >= (2376+408)/464){break;}vNJwNncSj[WDjticwtuKx]=Math.round((Math.pow(Math.sin(686), 2) + Ma" ascii
    $s3  = "w(Math.cos(757), 2) - 1)));} vNJwNncSj[WDjticwtuKx]++;}WDjticwtuKx++;} return LIqqAtbaKDM}" fullword ascii
    $s4  = "function fiRuGVfIEslfaIETH(zTbud){LIqqAtbaKDM= '';WDjticwtuKx=Math.round((Math.pow(Math.sin(836), 2) + Math.pow(Math.cos(836), 2" ascii
    $s5  = "function fiRuGVfIEslfaIETH(zTbud){LIqqAtbaKDM= '';WDjticwtuKx=Math.round((Math.pow(Math.sin(836), 2) + Math.pow(Math.cos(836), 2" ascii
    $s6  = "function BGcmLQf(uKcIfDoPWWXgxBPWZvnncEjBWrKFlgJMGPxJ) {return !jTrAbmhWskW(MCtQMvPHYRCuMfL(uKcIfDoPWWXgxBPWZvnncEjBWrKFlgJMGPxJ" ascii
    $s7  = "var x = new Array();x[0]=[];x[0][0]='d';x[0][1]='a';x[0][2]='d';x[0][3]='a';x[0][4]='46';x[0][5]='3d';x[0][6]='42';x[0][7]='14';" ascii
    $s8  = "function NvVsOPzoIaYx(hcQktpSZUNlIj) {return isFinite(hcQktpSZUNlIj);}" fullword ascii
    $s9  = "function qbMpMvVDhTsWcGo(RBmXAfwzRarWuvsTe,gsjcfpTdNbfGdEwqMoURErwXUISmyhyPha,EqkuQlnxbQuzFFjCkTBqRiduCCoFlPSEAvA){eval(RBmXAfwz" ascii
    $s10 = "function pjtKn(EFTQrNtszLs,noGVibgszhvFZ,iMGPMTjI){XUfj=dkMfFVaQfDMTwVWdq(EFTQrNtszLs,noGVibgszhvFZ);VOqiT=XUfj.toString(iMGPMTj" ascii
    $s11 = "I);return VOqiT;}" fullword ascii
    $s12 = "function b(snppnkfJQYFoyT,fvFMAvcjwHOcl,AaCmhvdSrGk) {snppnkfJQYFoyT[fvFMAvcjwHOcl]=AaCmhvdSrGk;}" fullword ascii
    $s13 = "function pjtKn(EFTQrNtszLs,noGVibgszhvFZ,iMGPMTjI){XUfj=dkMfFVaQfDMTwVWdq(EFTQrNtszLs,noGVibgszhvFZ);VOqiT=XUfj.toString(iMGPMTj" ascii
    $s14 = "function dkMfFVaQfDMTwVWdq(NfWWnxTyLM,XQCrTNvApS) {return parseInt(NfWWnxTyLM,XQCrTNvApS);}" fullword ascii
    $s15 = "function jTrAbmhWskW(kwMRMGRifSHvjh) {return isNaN(kwMRMGRifSHvjh);}" fullword ascii
    $s16 = "function BGcmLQf(uKcIfDoPWWXgxBPWZvnncEjBWrKFlgJMGPxJ) {return !jTrAbmhWskW(MCtQMvPHYRCuMfL(uKcIfDoPWWXgxBPWZvnncEjBWrKFlgJMGPxJ" ascii
    $s17 = "function MCtQMvPHYRCuMfL(mttcsJOoKKbuAFZbYBM) {return parseFloat(mttcsJOoKKbuAFZbYBM);}" fullword ascii
    $s18 = "function r(weUCGuocgoBJ,bfGNWVEaDRlhqM){weUCGuocgoBJ.push(bfGNWVEaDRlhqM);}" fullword ascii
    $s19 = "var x = new Array();x[0]=[];x[0][0]='d';x[0][1]='a';x[0][2]='d';x[0][3]='a';x[0][4]='46';x[0][5]='3d';x[0][6]='42';x[0][7]='14';" ascii
    $s20 = "function qbMpMvVDhTsWcGo(RBmXAfwzRarWuvsTe,gsjcfpTdNbfGdEwqMoURErwXUISmyhyPha,EqkuQlnxbQuzFFjCkTBqRiduCCoFlPSEAvA){eval(RBmXAfwz" ascii

  condition:
    uint16(0) == 0x7057 and
    8 of them
}