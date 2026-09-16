rule sig_20151216_6dd89281118af8e070694ec24a33088d {
  meta:
    description = "datamaliciousorder - file 20151216_6dd89281118af8e070694ec24a33088d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "949ea3c1bc69650427760576265a85d158686882416be39428918e6059f3d884"

  strings:
    $s1  = "th.pow(Math.cos(918), 2) - 1)); while(true) { if(kABqIuGmz[eFAksDLMqfm] > tGqMW[eFAksDLMqfm].length-(278+654)/932) { break; } if" ascii
    $s2  = "function ssrltBZGTcGXIkCok(tGqMW){NIFMCUpmEcr= '';eFAksDLMqfm=Math.round((Math.pow(Math.sin(525), 2) + Math.pow(Math.cos(525), 2" ascii
    $s3  = "ow(Math.cos(235), 2) - 1)));} kABqIuGmz[eFAksDLMqfm]++;}eFAksDLMqfm++;} return NIFMCUpmEcr}" fullword ascii
    $s4  = ") - 1));while(true){if (eFAksDLMqfm >= (1580+124)/284){break;}kABqIuGmz[eFAksDLMqfm]=Math.round((Math.pow(Math.sin(918), 2) + Ma" ascii
    $s5  = "function ssrltBZGTcGXIkCok(tGqMW){NIFMCUpmEcr= '';eFAksDLMqfm=Math.round((Math.pow(Math.sin(525), 2) + Math.pow(Math.cos(525), 2" ascii
    $s6  = "function eLoZOkYlAafIZiH(CPqiCOmPUrsEnTJUFQk) {return parseFloat(CPqiCOmPUrsEnTJUFQk);}" fullword ascii
    $s7  = "function tNwdvnf(LKnCkPvjYKfdYcxKzyHbZsazcydDcuVAJwFD) {return !cQpxcnNIafR(eLoZOkYlAafIZiH(LKnCkPvjYKfdYcxKzyHbZsazcydDcuVAJwFD" ascii
    $s8  = "var P = new Array();P[0]=[];P[0][0]='d';P[0][1]='a';P[0][2]='d';P[0][3]='a';P[0][4]='46';P[0][5]='3d';P[0][6]='42';P[0][7]='14';" ascii
    $s9  = "function aNIXXhvnDWgivYY(aRYklgBQgafZTFnRr,aNHeALVXKrwyhagYrtEroxJaKBWSdBREuJ,ISSzFLbLcbQqWSazPgSApwXAifMbevmzaoA){eval(aRYklgBQ" ascii
    $s10 = "function zDSiYvYCEClJWpCsK(JrpvmSeNCb,PrFKexavIc) {return parseInt(JrpvmSeNCb,PrFKexavIc);}" fullword ascii
    $s11 = "function E(DtfWzYkkpuyOrG,XFRawyYoDVffm,fCnhgXKDLgG) {DtfWzYkkpuyOrG[XFRawyYoDVffm]=fCnhgXKDLgG;}" fullword ascii
    $s12 = "function f(ybSZhSupcgup,cTaTAsEemIaDmd){ybSZhSupcgup.push(cTaTAsEemIaDmd);}" fullword ascii
    $s13 = "function QRAmv(tLqAbgngXPI,FNTmGxELLmrHL,ZEdGQReA){OBNZ=zDSiYvYCEClJWpCsK(tLqAbgngXPI,FNTmGxELLmrHL);gXCYO=OBNZ.toString(ZEdGQRe" ascii
    $s14 = "function aNIXXhvnDWgivYY(aRYklgBQgafZTFnRr,aNHeALVXKrwyhagYrtEroxJaKBWSdBREuJ,ISSzFLbLcbQqWSazPgSApwXAifMbevmzaoA){eval(aRYklgBQ" ascii
    $s15 = "function QISqmKjPPsvIiqgenHyRTObHRMAuDyeQulBQOeAPrfHxMKiREdkSTJ(VVbonChvwvYEA,kfpNDWujQfcjWZ){ return QXFTmUl[yelzKgUF[QRAmv(VVb" ascii
    $s16 = "var P = new Array();P[0]=[];P[0][0]='d';P[0][1]='a';P[0][2]='d';P[0][3]='a';P[0][4]='46';P[0][5]='3d';P[0][6]='42';P[0][7]='14';" ascii
    $s17 = "function QRAmv(tLqAbgngXPI,FNTmGxELLmrHL,ZEdGQReA){OBNZ=zDSiYvYCEClJWpCsK(tLqAbgngXPI,FNTmGxELLmrHL);gXCYO=OBNZ.toString(ZEdGQRe" ascii
    $s18 = "function tNwdvnf(LKnCkPvjYKfdYcxKzyHbZsazcydDcuVAJwFD) {return !cQpxcnNIafR(eLoZOkYlAafIZiH(LKnCkPvjYKfdYcxKzyHbZsazcydDcuVAJwFD" ascii
    $s19 = "A);return gXCYO;}" fullword ascii
    $s20 = "function TLKZYoZLYvty(RGHBBZOHcOPsx) {return isFinite(RGHBBZOHcOPsx);}" fullword ascii

  condition:
    uint16(0) == 0x6579 and
    8 of them
}