rule sig_20151210_59818f7533cfbe254c5ed4474b3c2e13 {
  meta:
    description = "datamaliciousorder - file 20151210_59818f7533cfbe254c5ed4474b3c2e13.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2c087300e509923b70823160fa3ced52f0da225f427b40f77f9747afc1a7c81"

  strings:
    $s1  = "function dRBQkFS(cSTQoWhuzRwNaoNcbKhbVxBbgTcBfIIvGGQv) {return !isNaN(parseFloat(cSTQoWhuzRwNaoNcbKhbVxBbgTcBfIIvGGQv)) && isFin" ascii
    $s2  = "function dRBQkFS(cSTQoWhuzRwNaoNcbKhbVxBbgTcBfIIvGGQv) {return !isNaN(parseFloat(cSTQoWhuzRwNaoNcbKhbVxBbgTcBfIIvGGQv)) && isFin" ascii
    $s3  = "function LptobRrkyYhOVUgOD(chSNY){htdhWeGrRDJ= '';for(tjXNlhrLmGn=(-467+467)/180; tjXNlhrLmGn < (294+638)/466; tjXNlhrLmGn++) {I" ascii
    $s4  = "} return htdhWeGrRDJ}" fullword ascii
    $s5  = " CqmUO;}function IlsZTxtchSAPdeS(qOljfoFAitKSgKvrS){eval(qOljfoFAitKSgKvrS)}" fullword ascii
    $s6  = "function FVMOZtmuthISmLxLpjxQtRlfXpGqxVgOhjHQBaSrnHcEcepNUwhyfM(GJLQmJQkxsLpx,TSnkDcbHgMFtAk){ return nuUHeQniVGbGH[GHrOX(GJLQmJ" ascii
    $s7  = "HTcPJZf=(-655+655)/217;while(true){if(HTcPJZf>=(123147+629)/967){break;}nuUHeQniVGbGH[HTcPJZf]=String.fromCharCode(HTcPJZf);HTcP" ascii
    $s8  = "function GHrOX(pjNrhXfxcwR,ZmZSLSNpjwIrH,RVPWPemn){Figj=parseInt(pjNrhXfxcwR,ZmZSLSNpjwIrH);CqmUO=Figj.toString(RVPWPemn);return" ascii
    $s9  = "function GHrOX(pjNrhXfxcwR,ZmZSLSNpjwIrH,RVPWPemn){Figj=parseInt(pjNrhXfxcwR,ZmZSLSNpjwIrH);CqmUO=Figj.toString(RVPWPemn);return" ascii
    $s10 = "HTcPJZf=(-655+655)/217;while(true){if(HTcPJZf>=(123147+629)/967){break;}nuUHeQniVGbGH[HTcPJZf]=String.fromCharCode(HTcPJZf);HTcP" ascii
    $s11 = "function CcwuIEatSxn(vLfVTqsL,AguErz){return vLfVTqsL.split(AguErz)}" fullword ascii
    $s12 = "function LptobRrkyYhOVUgOD(chSNY){htdhWeGrRDJ= '';for(tjXNlhrLmGn=(-467+467)/180; tjXNlhrLmGn < (294+638)/466; tjXNlhrLmGn++) {I" ascii
    $s13 = "function FVMOZtmuthISmLxLpjxQtRlfXpGqxVgOhjHQBaSrnHcEcepNUwhyfM(GJLQmJQkxsLpx,TSnkDcbHgMFtAk){ return nuUHeQniVGbGH[GHrOX(GJLQmJ" ascii
    $s14 = "ymptWiGC[tjXNlhrLmGn]=(-430+430)/120; while(true) { if(IymptWiGC[tjXNlhrLmGn] > chSNY[tjXNlhrLmGn].length-(-279+349)/70) { break" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}