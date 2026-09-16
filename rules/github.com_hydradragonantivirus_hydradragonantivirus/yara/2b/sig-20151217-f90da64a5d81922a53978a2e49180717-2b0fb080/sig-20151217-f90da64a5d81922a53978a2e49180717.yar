rule sig_20151217_f90da64a5d81922a53978a2e49180717 {
  meta:
    description = "datamaliciousorder - file 20151217_f90da64a5d81922a53978a2e49180717.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce113ee2bab36d9834a2e44368d5d3b818c6213853fece64b6b522a05c32fab5"

  strings:
    $s1  = "w(Math.cos(134), 2) - 1)));} XfSHSEQTR[jUUyspMkRTK]++;}jUUyspMkRTK++;} return bjCTTNHvVaw}" fullword ascii
    $s2  = "function AKdrOEONpZIhQLDcK(fiBDd){bjCTTNHvVaw= '';jUUyspMkRTK=Math.round((Math.pow(Math.sin(150), 2) + Math.pow(Math.cos(150), 2" ascii
    $s3  = ") - 1));while(true){if (jUUyspMkRTK >= (1751+37)/298){break;}XfSHSEQTR[jUUyspMkRTK]=Math.round((Math.pow(Math.sin(298), 2) + Mat" ascii
    $s4  = "h.pow(Math.cos(298), 2) - 1)); while(true) { if(XfSHSEQTR[jUUyspMkRTK] > fiBDd[jUUyspMkRTK].length-(-192+817)/625) { break; } if" ascii
    $s5  = "function AKdrOEONpZIhQLDcK(fiBDd){bjCTTNHvVaw= '';jUUyspMkRTK=Math.round((Math.pow(Math.sin(150), 2) + Math.pow(Math.cos(150), 2" ascii
    $s6  = "function nqTFDCW(piPYAZPSDVSXpKcUPvBqAzbjXAbLgpYMsFbg) {return !pRhAYtuKUgI(phqSpsIWNDfgpJZ(piPYAZPSDVSXpKcUPvBqAzbjXAbLgpYMsFbg" ascii
    $s7  = "var i = new Array();i[0]=[];i[0][0]='d';i[0][1]='a';i[0][2]='d';i[0][3]='a';i[0][4]='46';i[0][5]='3d';i[0][6]='42';i[0][7]='14';" ascii
    $s8  = "function eLICYtFvYfOhWkHcqumJFbILEDzbLQhHwXbKmbsIphpxjDTpKqycHv(KaTiiRWFhSzJO,wzwAErEsOedkWv){ return QhsqsaZ[KLtqyrKs[YdeKg(KaT" ascii
    $s9  = "function YdeKg(xjCntowEOzO,hJyFxUIsKrIpc,eWMtxOlQ){xFoU=YcszVtVwEEFwOuqDT(xjCntowEOzO,hJyFxUIsKrIpc);jpfrC=xFoU.toString(eWMtxOl" ascii
    $s10 = "function phqSpsIWNDfgpJZ(GPGqBLghVAxwqkjcZFY) {return parseFloat(GPGqBLghVAxwqkjcZFY);}" fullword ascii
    $s11 = "function eLICYtFvYfOhWkHcqumJFbILEDzbLQhHwXbKmbsIphpxjDTpKqycHv(KaTiiRWFhSzJO,wzwAErEsOedkWv){ return QhsqsaZ[KLtqyrKs[YdeKg(KaT" ascii
    $s12 = "function nqTFDCW(piPYAZPSDVSXpKcUPvBqAzbjXAbLgpYMsFbg) {return !pRhAYtuKUgI(phqSpsIWNDfgpJZ(piPYAZPSDVSXpKcUPvBqAzbjXAbLgpYMsFbg" ascii
    $s13 = "function C(hwgdqPLrxeNoka,EDDIVdDtdyDKJ,DmZZAffYWZR) {hwgdqPLrxeNoka[EDDIVdDtdyDKJ]=DmZZAffYWZR;}" fullword ascii
    $s14 = "function W(pRcDlqdJPzAb,tLWgnXjuKJHWSb){pRcDlqdJPzAb.push(tLWgnXjuKJHWSb);}" fullword ascii
    $s15 = "Q);return jpfrC;}" fullword ascii
    $s16 = "function ABxoramBxjqnqFv(CzLpJYYZemIdxBsDb,cHHNZzhTPEYhTAlWZbZOrvijqXJWnmisSX,qVKItwvWyciinvusQMcTZpIhQQDgnRumjFo){eval(CzLpJYYZ" ascii
    $s17 = "function zuybzzNcEEws(fwmnHCBLmMFNh) {return isFinite(fwmnHCBLmMFNh);}" fullword ascii
    $s18 = "function YdeKg(xjCntowEOzO,hJyFxUIsKrIpc,eWMtxOlQ){xFoU=YcszVtVwEEFwOuqDT(xjCntowEOzO,hJyFxUIsKrIpc);jpfrC=xFoU.toString(eWMtxOl" ascii
    $s19 = "var i = new Array();i[0]=[];i[0][0]='d';i[0][1]='a';i[0][2]='d';i[0][3]='a';i[0][4]='46';i[0][5]='3d';i[0][6]='42';i[0][7]='14';" ascii
    $s20 = "function YcszVtVwEEFwOuqDT(wkWswvmktC,fvLBgAJdQQ) {return parseInt(wkWswvmktC,fvLBgAJdQQ);}" fullword ascii

  condition:
    uint16(0) == 0x4c4b and
    8 of them
}