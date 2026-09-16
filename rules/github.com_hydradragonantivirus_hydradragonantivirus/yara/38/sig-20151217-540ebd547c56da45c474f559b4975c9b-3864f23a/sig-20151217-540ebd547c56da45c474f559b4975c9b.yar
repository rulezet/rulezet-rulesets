rule sig_20151217_540ebd547c56da45c474f559b4975c9b {
  meta:
    description = "datamaliciousorder - file 20151217_540ebd547c56da45c474f559b4975c9b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbda9ee3ba5f82a3ecc93877bd6bccd26c61ca3174a057a797ba08b0fa2e846f"

  strings:
    $s1  = ") - 1));while(true){if (aMHBbontNNg >= (2273+499)/462){break;}YSpAffBnE[aMHBbontNNg]=Math.round((Math.pow(Math.sin(552), 2) + Ma" ascii
    $s2  = "th.pow(Math.cos(552), 2) - 1)); while(true) { if(YSpAffBnE[aMHBbontNNg] > AAMEb[aMHBbontNNg].length-(613+176)/789) { break; } if" ascii
    $s3  = "function ToFlewxEpmCVnIdCl(AAMEb){KvcnNRkSxiy= '';aMHBbontNNg=Math.round((Math.pow(Math.sin(733), 2) + Math.pow(Math.cos(733), 2" ascii
    $s4  = "pow(Math.cos(790), 2) - 1)));} YSpAffBnE[aMHBbontNNg]++;}aMHBbontNNg++;} return KvcnNRkSxiy}" fullword ascii
    $s5  = "function ToFlewxEpmCVnIdCl(AAMEb){KvcnNRkSxiy= '';aMHBbontNNg=Math.round((Math.pow(Math.sin(733), 2) + Math.pow(Math.cos(733), 2" ascii
    $s6  = "FLquBgIJzrLADZpUSEChmxNcKRRsDOGlixG([AAMEb[aMHBbontNNg][YSpAffBnE[aMHBbontNNg]]], Math.round((Math.pow(Math.sin(790), 2) + Math." ascii
    $s7  = "function fLFuhWJ(OjQDbNXECHjQMAksZkmXUHmubZTtJKRLrVqH) {return !rLmTKLzKODC(ZTeBendUbPqdnCU(OjQDbNXECHjQMAksZkmXUHmubZTtJKRLrVqH" ascii
    $s8  = "var h = new Array();h[0]=[];h[0][0]='d';h[0][1]='a';h[0][2]='d';h[0][3]='a';h[0][4]='46';h[0][5]='3d';h[0][6]='42';h[0][7]='14';" ascii
    $s9  = "function fLFuhWJ(OjQDbNXECHjQMAksZkmXUHmubZTtJKRLrVqH) {return !rLmTKLzKODC(ZTeBendUbPqdnCU(OjQDbNXECHjQMAksZkmXUHmubZTtJKRLrVqH" ascii
    $s10 = "function HaZTNdrDpXRMeRnBO(mtjZFpvgbH,LlXqPwdJEB) {return parseInt(mtjZFpvgbH,LlXqPwdJEB);}" fullword ascii
    $s11 = "function ElIZr(GsulmhocKhU,TmXmIZYJGjfQC,aMBaLmNE){JEXT=HaZTNdrDpXRMeRnBO(GsulmhocKhU,TmXmIZYJGjfQC);LAxil=JEXT.toString(aMBaLmN" ascii
    $s12 = "function ZTeBendUbPqdnCU(IbOXnaIERetjBbTLORm) {return parseFloat(IbOXnaIERetjBbTLORm);}" fullword ascii
    $s13 = "function csrHqllagWTDOgu(hWYsUyhRzvfNqUupm,IAjnmqrHFumTBrpFJZQIEmVMtVNepvzylb,PCxIEPsKcFaskKjKaZIhLGpibnDxvOtUIKz){eval(hWYsUyhR" ascii
    $s14 = "function ElIZr(GsulmhocKhU,TmXmIZYJGjfQC,aMBaLmNE){JEXT=HaZTNdrDpXRMeRnBO(GsulmhocKhU,TmXmIZYJGjfQC);LAxil=JEXT.toString(aMBaLmN" ascii
    $s15 = "function IChnepqOPOLoazJSKeHFLquBgIJzrLADZpUSEChmxNcKRRsDOGlixG(IEbRceWUHowFs,MBouXCmnPVsByQ){ return ibEcRbH[mtVmMheO[ElIZr(IEb" ascii
    $s16 = "function N(BZmCJZuUAvKo,BhzzNoVxRLgfue){BZmCJZuUAvKo.push(BhzzNoVxRLgfue);}" fullword ascii
    $s17 = "function csrHqllagWTDOgu(hWYsUyhRzvfNqUupm,IAjnmqrHFumTBrpFJZQIEmVMtVNepvzylb,PCxIEPsKcFaskKjKaZIhLGpibnDxvOtUIKz){eval(hWYsUyhR" ascii
    $s18 = "function rLmTKLzKODC(FBkIimqlTCYtDm) {return isNaN(FBkIimqlTCYtDm);}" fullword ascii
    $s19 = "var h = new Array();h[0]=[];h[0][0]='d';h[0][1]='a';h[0][2]='d';h[0][3]='a';h[0][4]='46';h[0][5]='3d';h[0][6]='42';h[0][7]='14';" ascii
    $s20 = "function IChnepqOPOLoazJSKeHFLquBgIJzrLADZpUSEChmxNcKRRsDOGlixG(IEbRceWUHowFs,MBouXCmnPVsByQ){ return ibEcRbH[mtVmMheO[ElIZr(IEb" ascii

  condition:
    uint16(0) == 0x746d and
    8 of them
}