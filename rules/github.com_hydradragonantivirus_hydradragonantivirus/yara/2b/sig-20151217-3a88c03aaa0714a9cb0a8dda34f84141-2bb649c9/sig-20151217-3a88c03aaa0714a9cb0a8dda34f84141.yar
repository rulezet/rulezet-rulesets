rule sig_20151217_3a88c03aaa0714a9cb0a8dda34f84141 {
  meta:
    description = "datamaliciousorder - file 20151217_3a88c03aaa0714a9cb0a8dda34f84141.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5236d644e74059a2dd34ba6de1d11930c75680ba5d38481ea45ddb207a1f6e48"

  strings:
    $s1  = "ath.cos(974), 2) - 1)));} DYyGbpWfN[DblnumDHeUj]++;}DblnumDHeUj++;} return HZqprTniPHA}" fullword ascii
    $s2  = "function lbGqueJctWQmEvhPk(VTepX){HZqprTniPHA= '';DblnumDHeUj=Math.round((Math.pow(Math.sin(89), 2) + Math.pow(Math.cos(89), 2) " ascii
    $s3  = ".pow(Math.cos(330), 2) - 1)); while(true) { if(DYyGbpWfN[DblnumDHeUj] > VTepX[DblnumDHeUj].length-(-40+310)/270) { break; } if (" ascii
    $s4  = "- 1));while(true){if (DblnumDHeUj >= (1672+590)/377){break;}DYyGbpWfN[DblnumDHeUj]=Math.round((Math.pow(Math.sin(330), 2) + Math" ascii
    $s5  = "function lbGqueJctWQmEvhPk(VTepX){HZqprTniPHA= '';DblnumDHeUj=Math.round((Math.pow(Math.sin(89), 2) + Math.pow(Math.cos(89), 2) " ascii
    $s6  = "function rFnpl(RMrumZzRzFM,IkBRpakxKGaMq,vDfkHCou){vShn=LOGKzWMppvCCVGGic(RMrumZzRzFM,IkBRpakxKGaMq);vlehr=vShn.toString(vDfkHCo" ascii
    $s7  = "function rFnpl(RMrumZzRzFM,IkBRpakxKGaMq,vDfkHCou){vShn=LOGKzWMppvCCVGGic(RMrumZzRzFM,IkBRpakxKGaMq);vlehr=vShn.toString(vDfkHCo" ascii
    $s8  = "function LOGKzWMppvCCVGGic(RazCmPcRqH,JRDuArKMNW) {return parseInt(RazCmPcRqH,JRDuArKMNW);}" fullword ascii
    $s9  = "function dBFYsIVAjANqSFo(BjYDuoAThmiaIUujp,OhqDVOUWrflOZJKYIQqfiTXLpRrWYEPEhT,iVeXupGYvYagpCOMDyEAZvZROBsNhmypaeq){eval(BjYDuoAT" ascii
    $s10 = "function NsmhDBw(LFyINPrdDmvGPhsYOqZHyjyJcnrJhZzWefxM) {return !rjlIMXWJUad(vALrWrCntlqvDJO(LFyINPrdDmvGPhsYOqZHyjyJcnrJhZzWefxM" ascii
    $s11 = "function dBFYsIVAjANqSFo(BjYDuoAThmiaIUujp,OhqDVOUWrflOZJKYIQqfiTXLpRrWYEPEhT,iVeXupGYvYagpCOMDyEAZvZROBsNhmypaeq){eval(BjYDuoAT" ascii
    $s12 = "var e = new Array();e[0]=[];e[0][0]='d';e[0][1]='a';e[0][2]='d';e[0][3]='a';e[0][4]='46';e[0][5]='3d';e[0][6]='42';e[0][7]='14';" ascii
    $s13 = "var e = new Array();e[0]=[];e[0][0]='d';e[0][1]='a';e[0][2]='d';e[0][3]='a';e[0][4]='46';e[0][5]='3d';e[0][6]='42';e[0][7]='14';" ascii
    $s14 = "function D(YurgffeoQRNzHf,wBhpHgqDbZjDO,GryxXSLiTFJ) {YurgffeoQRNzHf[wBhpHgqDbZjDO]=GryxXSLiTFJ;}" fullword ascii
    $s15 = "function NsmhDBw(LFyINPrdDmvGPhsYOqZHyjyJcnrJhZzWefxM) {return !rjlIMXWJUad(vALrWrCntlqvDJO(LFyINPrdDmvGPhsYOqZHyjyJcnrJhZzWefxM" ascii
    $s16 = "function vALrWrCntlqvDJO(ZgzcFkUMwjAuWInlUmt) {return parseFloat(ZgzcFkUMwjAuWInlUmt);}" fullword ascii
    $s17 = "function rjlIMXWJUad(vRHxuXbpsEFQLj) {return isNaN(vRHxuXbpsEFQLj);}" fullword ascii
    $s18 = "function gxuyhSzaWrCQsfrZNwNMSobVcgxJhJvMtgRvxWeZbCRnENOrAbxCVl(OodUWLoxtOOMK,vGoYUGGTEapbUP){ return dGRbMLB[HtioLTDD[rFnpl(Ood" ascii
    $s19 = "u);return vlehr;}" fullword ascii
    $s20 = "function pqPfzgbVZSmZ(oHpjyPNJTIODF) {return isFinite(oHpjyPNJTIODF);}" fullword ascii

  condition:
    uint16(0) == 0x7448 and
    8 of them
}