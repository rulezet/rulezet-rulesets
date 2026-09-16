rule sig_20151217_66462294eeeb1651df824ba30e21dce0 {
  meta:
    description = "datamaliciousorder - file 20151217_66462294eeeb1651df824ba30e21dce0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "662768a417956df4552a660d7339d067387c6c7e08edc6ed98bc3a34bad7f7ed"

  strings:
    $s1  = "th.pow(Math.cos(110), 2) - 1)); while(true) { if(XVpidEctD[DXiswCVFBDn] > EEOlr[DXiswCVFBDn].length-(-334+957)/623) { break; } i" ascii
    $s2  = "function uHZTopQcMfccooFto(EEOlr){tNBEXftXxRB= '';DXiswCVFBDn=Math.round((Math.pow(Math.sin(716), 2) + Math.pow(Math.cos(716), 2" ascii
    $s3  = ") - 1));while(true){if (DXiswCVFBDn >= (3201+501)/617){break;}XVpidEctD[DXiswCVFBDn]=Math.round((Math.pow(Math.sin(110), 2) + Ma" ascii
    $s4  = "w(Math.cos(658), 2) - 1)));} XVpidEctD[DXiswCVFBDn]++;}DXiswCVFBDn++;} return tNBEXftXxRB}" fullword ascii
    $s5  = "function eNIwQpVGPQUceeZsyCZebkulrsjVbtEYTtfemrarRzaXOypyBiEVOM(xhSzUxhCYjeeM,ADZfwkEYEzYUhp){ return lAsoeMs[EaVHBTVh[KEWGr(xhS" ascii
    $s6  = "function eNIwQpVGPQUceeZsyCZebkulrsjVbtEYTtfemrarRzaXOypyBiEVOM(xhSzUxhCYjeeM,ADZfwkEYEzYUhp){ return lAsoeMs[EaVHBTVh[KEWGr(xhS" ascii
    $s7  = "function uHZTopQcMfccooFto(EEOlr){tNBEXftXxRB= '';DXiswCVFBDn=Math.round((Math.pow(Math.sin(716), 2) + Math.pow(Math.cos(716), 2" ascii
    $s8  = "function gKNUGUn(QhhNRBpuHDbGPgDlUNWwWiDIxdFExPKLyuaV) {return !eseQSbUfPeO(nGbMiEjoVmTuprN(QhhNRBpuHDbGPgDlUNWwWiDIxdFExPKLyuaV" ascii
    $s9  = "var D = new Array();D[0]=[];D[0][0]='d';D[0][1]='a';D[0][2]='d';D[0][3]='a';D[0][4]='46';D[0][5]='3d';D[0][6]='42';D[0][7]='14';" ascii
    $s10 = "G);return IiiZt;}" fullword ascii
    $s11 = "function gKNUGUn(QhhNRBpuHDbGPgDlUNWwWiDIxdFExPKLyuaV) {return !eseQSbUfPeO(nGbMiEjoVmTuprN(QhhNRBpuHDbGPgDlUNWwWiDIxdFExPKLyuaV" ascii
    $s12 = "function v(kZUjyXMMqBsc,mDlxMoQbNBAVKJ){kZUjyXMMqBsc.push(mDlxMoQbNBAVKJ);}" fullword ascii
    $s13 = "function GHaXLlMeilxXRhm(OpXqVEpvFyDXiTSIE,xkXlzBJZzrbZzYQnqsQjGgJXjaYDMUpTBh,FYczzFwSUugyUFQtOgLCdgouVHSaQYGfodY){eval(OpXqVEpv" ascii
    $s14 = "function a(BykKHLvkLjwewb,yXQyYUnfDWDbv,hWviPdZsQmo) {BykKHLvkLjwewb[yXQyYUnfDWDbv]=hWviPdZsQmo;}" fullword ascii
    $s15 = "function nGbMiEjoVmTuprN(XReNkCCWyzJGfKbgXWC) {return parseFloat(XReNkCCWyzJGfKbgXWC);}" fullword ascii
    $s16 = "function HDVLXHQlBikUdNenh(iRevWolBpf,SZvqWDtNQn) {return parseInt(iRevWolBpf,SZvqWDtNQn);}" fullword ascii
    $s17 = "function GHaXLlMeilxXRhm(OpXqVEpvFyDXiTSIE,xkXlzBJZzrbZzYQnqsQjGgJXjaYDMUpTBh,FYczzFwSUugyUFQtOgLCdgouVHSaQYGfodY){eval(OpXqVEpv" ascii
    $s18 = "function KEWGr(pxtXSkXyMUG,wbkPBYQSTHonq,DMFynpFG){NPgb=HDVLXHQlBikUdNenh(pxtXSkXyMUG,wbkPBYQSTHonq);IiiZt=NPgb.toString(DMFynpF" ascii
    $s19 = "function KEWGr(pxtXSkXyMUG,wbkPBYQSTHonq,DMFynpFG){NPgb=HDVLXHQlBikUdNenh(pxtXSkXyMUG,wbkPBYQSTHonq);IiiZt=NPgb.toString(DMFynpF" ascii
    $s20 = "var D = new Array();D[0]=[];D[0][0]='d';D[0][1]='a';D[0][2]='d';D[0][3]='a';D[0][4]='46';D[0][5]='3d';D[0][6]='42';D[0][7]='14';" ascii

  condition:
    uint16(0) == 0x6145 and
    8 of them
}