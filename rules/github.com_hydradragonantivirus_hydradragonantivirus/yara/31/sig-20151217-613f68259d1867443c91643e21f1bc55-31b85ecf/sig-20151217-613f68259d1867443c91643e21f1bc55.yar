rule sig_20151217_613f68259d1867443c91643e21f1bc55 {
  meta:
    description = "datamaliciousorder - file 20151217_613f68259d1867443c91643e21f1bc55.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30d89054bf32a519739030224ea9d7851bdb95a56178cb6fbf9eccfe8c699de9"

  strings:
    $s1  = "th.pow(Math.cos(941), 2) - 1)); while(true) { if(UzkNcpfRs[VxRjdWLqoti] > vkJQo[VxRjdWLqoti].length-(360+131)/491) { break; } if" ascii
    $s2  = "ow(Math.cos(971), 2) - 1)));} UzkNcpfRs[VxRjdWLqoti]++;}VxRjdWLqoti++;} return NGDbsLOaIWU}" fullword ascii
    $s3  = ") - 1));while(true){if (VxRjdWLqoti >= (-355+973)/103){break;}UzkNcpfRs[VxRjdWLqoti]=Math.round((Math.pow(Math.sin(941), 2) + Ma" ascii
    $s4  = "function UVeiwapUGcAqIdxMA(vkJQo){NGDbsLOaIWU= '';VxRjdWLqoti=Math.round((Math.pow(Math.sin(607), 2) + Math.pow(Math.cos(607), 2" ascii
    $s5  = "function SHNrrTr(QxaysnMPbcVDeoRwutvzgNzTWWQyaspKzsxw) {return !VPYFPEcWgBu(oTmBsjBTvrmWJoZ(QxaysnMPbcVDeoRwutvzgNzTWWQyaspKzsxw" ascii
    $s6  = "function UVeiwapUGcAqIdxMA(vkJQo){NGDbsLOaIWU= '';VxRjdWLqoti=Math.round((Math.pow(Math.sin(607), 2) + Math.pow(Math.cos(607), 2" ascii
    $s7  = "var B = new Array();B[0]=[];B[0][0]='d';B[0][1]='a';B[0][2]='d';B[0][3]='a';B[0][4]='46';B[0][5]='3d';B[0][6]='42';B[0][7]='14';" ascii
    $s8  = "function mSnUqEcidAYZjKobl(EIDtEoqwmi,nZqPbeILKk) {return parseInt(EIDtEoqwmi,nZqPbeILKk);}" fullword ascii
    $s9  = "var B = new Array();B[0]=[];B[0][0]='d';B[0][1]='a';B[0][2]='d';B[0][3]='a';B[0][4]='46';B[0][5]='3d';B[0][6]='42';B[0][7]='14';" ascii
    $s10 = "function dtcqIsauHyBHzKV(TYeZGTfHaZCcZYkmu,TVWdPmgVoanEgKfstwNrrvgecoOxWXnPHC,KoTiiScQnTUnKcTTpvPfVGFpQRQFkRCoOtZ){eval(TYeZGTfH" ascii
    $s11 = "function dtcqIsauHyBHzKV(TYeZGTfHaZCcZYkmu,TVWdPmgVoanEgKfstwNrrvgecoOxWXnPHC,KoTiiScQnTUnKcTTpvPfVGFpQRQFkRCoOtZ){eval(TYeZGTfH" ascii
    $s12 = "function VPYFPEcWgBu(yJddYvHoeBsngh) {return isNaN(yJddYvHoeBsngh);}" fullword ascii
    $s13 = "function IKyBsugMUMWV(dLxKGKaTUZTEt) {return isFinite(dLxKGKaTUZTEt);}" fullword ascii
    $s14 = "function VBrXj(NhYcPDOkSLb,ZDmraytwrtXAw,WqwvkmDM){XbxR=mSnUqEcidAYZjKobl(NhYcPDOkSLb,ZDmraytwrtXAw);BNCba=XbxR.toString(WqwvkmD" ascii
    $s15 = "function VBrXj(NhYcPDOkSLb,ZDmraytwrtXAw,WqwvkmDM){XbxR=mSnUqEcidAYZjKobl(NhYcPDOkSLb,ZDmraytwrtXAw);BNCba=XbxR.toString(WqwvkmD" ascii
    $s16 = "function R(cWAVTMqQzKai,giQsZLttBXEJoO){cWAVTMqQzKai.push(giQsZLttBXEJoO);}" fullword ascii
    $s17 = "M);return BNCba;}" fullword ascii
    $s18 = "function oTmBsjBTvrmWJoZ(raPEXVXRoPHeQyBEnQH) {return parseFloat(raPEXVXRoPHeQyBEnQH);}" fullword ascii
    $s19 = "function SHNrrTr(QxaysnMPbcVDeoRwutvzgNzTWWQyaspKzsxw) {return !VPYFPEcWgBu(oTmBsjBTvrmWJoZ(QxaysnMPbcVDeoRwutvzgNzTWWQyaspKzsxw" ascii
    $s20 = "function ZOCNZzDdBsQiHJeoHnljCpfXkkMgimNcdabBtWOVCmktZvZPkVxAPu(nwhjZEMiQBlrg,bHXNgKsnMwYTxL){ return HRghPdN[pZAbuPOr[VBrXj(nwh" ascii

  condition:
    uint16(0) == 0x5a70 and
    8 of them
}