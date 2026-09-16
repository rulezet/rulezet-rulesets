rule sig_20151209_3508752afdb0433aac7b17ad6dbdf2d2 {
  meta:
    description = "datamaliciousorder - file 20151209_3508752afdb0433aac7b17ad6dbdf2d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7483a3e61d074cd1cbd32ad0c67f40928bec36c008915c01c5dcbbed501f6caa"

  strings:
    $s1  = "function hNyQCNE(APFKYkVAcCoqkSzARFOzbUgKSTDkdKqAchVB) {return !isNaN(parseFloat(APFKYkVAcCoqkSzARFOzbUgKSTDkdKqAchVB)) && isFin" ascii
    $s2  = "function hNyQCNE(APFKYkVAcCoqkSzARFOzbUgKSTDkdKqAchVB) {return !isNaN(parseFloat(APFKYkVAcCoqkSzARFOzbUgKSTDkdKqAchVB)) && isFin" ascii
    $s3  = "+;}} return lHKvyYXYers}" fullword ascii
    $s4  = "push(\"32\");S.push(\"61\");S.push(\"32\");S.push(\"87\");S.push(\"83\");S.push(\"99\");S.push(\"114\");S.push(\"105\");S.push(" ascii
    $s5  = "RBNBG)}function FGiVm(QsTURfEmxFV,hCDKfhBaAvZGA,owhgjovf){ruKF=parseInt(QsTURfEmxFV,hCDKfhBaAvZGA);FjrbI=ruKF.toString(owhgjovf)" ascii
    $s6  = "function BTbPLhuBwOxfqacsC(XRGQd){lHKvyYXYers= '';for(AKblLuHsZiN=(-602+602)/640; AKblLuHsZiN < (289+347)/318; AKblLuHsZiN++) {A" ascii
    $s7  = "function xJYylIwWFBobysPHhOpUmJvFMezUnyXMMNPDYEEsaGXPVsHQLfFwwT(xlepchKkbONpO,fpHPmrZSMdAHij){ return SIxgTTLqgWBVM[FGiVm(xlepch" ascii
    $s8  = "push(\"32\");N.push(\"32\");N.push(\"125\");N.push(\"59\");N.push(\"32\");N.push(\"105\");N.push(\"84\");N.push(\"109\");N.push(" ascii
    $s9  = "function xJYylIwWFBobysPHhOpUmJvFMezUnyXMMNPDYEEsaGXPVsHQLfFwwT(xlepchKkbONpO,fpHPmrZSMdAHij){ return SIxgTTLqgWBVM[FGiVm(xlepch" ascii
    $s10 = "push(\"100\");N.push(\"121\");N.push(\"41\");N.push(\"59\");N.push(\"32\");N.push(\"105\");N.push(\"102\");N.push(\"32\");N.push" ascii
    $s11 = "var SIxgTTLqgWBVM=[];for(hbRBNBG=(-988+988)/689;hbRBNBG<(43993+295)/346;hbRBNBG++){SIxgTTLqgWBVM[hbRBNBG]=String.fromCharCode(hb" ascii
    $s12 = "function eUrKvvDGpmr(oKYrjCGN,XIWmmT){return oKYrjCGN.split(XIWmmT)}" fullword ascii
    $s13 = "function BTbPLhuBwOxfqacsC(XRGQd){lHKvyYXYers= '';for(AKblLuHsZiN=(-602+602)/640; AKblLuHsZiN < (289+347)/318; AKblLuHsZiN++) {A" ascii
    $s14 = "push(\"44\");N.push(\"55\");N.push(\"54\");N.push(\"53\");N.push(\"51\");N.push(\"50\");N.push(\"56\");N.push(\"56\");N.push(\"5" ascii
    $s15 = "push(\"32\");N.push(\"32\");N.push(\"32\");N.push(\"32\");N.push(\"32\");N.push(\"32\");N.push(\"32\");N.push(\"32\");N.push(\"3" ascii
    $s16 = "JaJdvGAP[AKblLuHsZiN]=(-969+969)/100; while(true) { if(AJaJdvGAP[AKblLuHsZiN] > XRGQd[AKblLuHsZiN].length-(-75+790)/715) { break" ascii
    $s17 = ";return FjrbI;}function NQgbLbLgufyiqsu(mCgxIFHyfDXwPPoyX){eval(mCgxIFHyfDXwPPoyX)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}