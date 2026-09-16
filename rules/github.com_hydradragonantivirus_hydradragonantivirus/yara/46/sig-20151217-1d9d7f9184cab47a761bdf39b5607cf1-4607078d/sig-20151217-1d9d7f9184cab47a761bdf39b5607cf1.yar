rule sig_20151217_1d9d7f9184cab47a761bdf39b5607cf1 {
  meta:
    description = "datamaliciousorder - file 20151217_1d9d7f9184cab47a761bdf39b5607cf1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "779fea58bee76bf9a12a4d42ee1a32f2b6f9374d32944d72a7be8d1e3964798d"

  strings:
    $s1  = "function QCNooSIQiOcxqYzkJ(hLNeg){pXlTAHpGefg= '';jfBMUKcWnLA=Math.round((Math.pow(Math.sin(821), 2) + Math.pow(Math.cos(821), 2" ascii
    $s2  = "(Math.cos(358), 2) - 1)));} fiMxhdUfR[jfBMUKcWnLA]++;}jfBMUKcWnLA++;} return pXlTAHpGefg}" fullword ascii
    $s3  = "h.pow(Math.cos(798), 2) - 1)); while(true) { if(fiMxhdUfR[jfBMUKcWnLA] > hLNeg[jfBMUKcWnLA].length-(-727+735)/8) { break; } if (" ascii
    $s4  = ") - 1));while(true){if (jfBMUKcWnLA >= (-158+350)/32){break;}fiMxhdUfR[jfBMUKcWnLA]=Math.round((Math.pow(Math.sin(798), 2) + Mat" ascii
    $s5  = "function QCNooSIQiOcxqYzkJ(hLNeg){pXlTAHpGefg= '';jfBMUKcWnLA=Math.round((Math.pow(Math.sin(821), 2) + Math.pow(Math.cos(821), 2" ascii
    $s6  = "function HuDiJTS(xDHMIvPjMYIIRpRHJtnLMOOYsKBZiHbVTpar) {return !WeWwBbnhIsu(enliRaMOPGuuAxQ(xDHMIvPjMYIIRpRHJtnLMOOYsKBZiHbVTpar" ascii
    $s7  = "var p = new Array();p[0]=[];p[0][0]='d';p[0][1]='a';p[0][2]='d';p[0][3]='a';p[0][4]='46';p[0][5]='3d';p[0][6]='42';p[0][7]='14';" ascii
    $s8  = "function YlmbUelVrmsEfUa(YXwSBHZUkKCjUFZIl,qIjSjpeiIMpRYXbqgAGlVVYhKgsPfIBzYG,uoHmvKmeHsvZTiATCdCzwqEmmGLAGbIorHg){eval(YXwSBHZU" ascii
    $s9  = "function rxJCSpSuImHD(vjiXtUscZErYa) {return isFinite(vjiXtUscZErYa);}" fullword ascii
    $s10 = "function P(zaUUqmPqJdxUeS,XriMvTXHPTwWU,HczlWBgUeDa) {zaUUqmPqJdxUeS[XriMvTXHPTwWU]=HczlWBgUeDa;}" fullword ascii
    $s11 = "var p = new Array();p[0]=[];p[0][0]='d';p[0][1]='a';p[0][2]='d';p[0][3]='a';p[0][4]='46';p[0][5]='3d';p[0][6]='42';p[0][7]='14';" ascii
    $s12 = "function qYKoDHXWHsyxbrXOFBnEeckWPigWYAuWbvkEEvyWGgPpqqImnUSzyA(pXHOqpqGzVhlk,PMySnqbciyKmkZ){ return CvZmHQD[zcUoCOEL[dEuIh(pXH" ascii
    $s13 = "function dcLzUAhDTtXTtczqX(fxKLczEoDC,doCPoIyvSQ) {return parseInt(fxKLczEoDC,doCPoIyvSQ);}" fullword ascii
    $s14 = "function enliRaMOPGuuAxQ(cWzgallhSNjuYcmHFWK) {return parseFloat(cWzgallhSNjuYcmHFWK);}" fullword ascii
    $s15 = "function dEuIh(rnHOmUAgaTs,yuyWRTxlbGprN,sLepmDJK){CHjk=dcLzUAhDTtXTtczqX(rnHOmUAgaTs,yuyWRTxlbGprN);lArwY=CHjk.toString(sLepmDJ" ascii
    $s16 = "function qYKoDHXWHsyxbrXOFBnEeckWPigWYAuWbvkEEvyWGgPpqqImnUSzyA(pXHOqpqGzVhlk,PMySnqbciyKmkZ){ return CvZmHQD[zcUoCOEL[dEuIh(pXH" ascii
    $s17 = "K);return lArwY;}" fullword ascii
    $s18 = "function WeWwBbnhIsu(xTQdQyUaBOFpck) {return isNaN(xTQdQyUaBOFpck);}" fullword ascii
    $s19 = "function dEuIh(rnHOmUAgaTs,yuyWRTxlbGprN,sLepmDJK){CHjk=dcLzUAhDTtXTtczqX(rnHOmUAgaTs,yuyWRTxlbGprN);lArwY=CHjk.toString(sLepmDJ" ascii
    $s20 = "function HuDiJTS(xDHMIvPjMYIIRpRHJtnLMOOYsKBZiHbVTpar) {return !WeWwBbnhIsu(enliRaMOPGuuAxQ(xDHMIvPjMYIIRpRHJtnLMOOYsKBZiHbVTpar" ascii

  condition:
    uint16(0) == 0x637a and
    8 of them
}