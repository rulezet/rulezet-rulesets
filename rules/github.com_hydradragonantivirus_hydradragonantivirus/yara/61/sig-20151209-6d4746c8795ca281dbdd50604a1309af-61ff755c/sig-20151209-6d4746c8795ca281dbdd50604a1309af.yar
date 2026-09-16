rule sig_20151209_6d4746c8795ca281dbdd50604a1309af {
  meta:
    description = "datamaliciousorder - file 20151209_6d4746c8795ca281dbdd50604a1309af.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af46490af3ab38dd92c048d117d27dc4c8e60ad2454412f55bc1ba6729a94477"

  strings:
    $s1  = "function RYSAbsE(pKGYqbsVbeuRMMKNoTLXXKwwenvJleYzHFOv) {return !isNaN(parseFloat(pKGYqbsVbeuRMMKNoTLXXKwwenvJleYzHFOv)) && isFin" ascii
    $s2  = "function RYSAbsE(pKGYqbsVbeuRMMKNoTLXXKwwenvJleYzHFOv) {return !isNaN(parseFloat(pKGYqbsVbeuRMMKNoTLXXKwwenvJleYzHFOv)) && isFin" ascii
    $s3  = "function SbEgtqfoXXBXdCrOj(DhPfV){hcMtFFEJsTN= '';for(XuvPloJXDRm=(-572+572)/816; XuvPloJXDRm < (133+417)/275; XuvPloJXDRm++) {S" ascii
    $s4  = "function SbEgtqfoXXBXdCrOj(DhPfV){hcMtFFEJsTN= '';for(XuvPloJXDRm=(-572+572)/816; XuvPloJXDRm < (133+417)/275; XuvPloJXDRm++) {S" ascii
    $s5  = "fCuwkuaB[XuvPloJXDRm]=(-112+112)/235; while(true) { if(SfCuwkuaB[XuvPloJXDRm] > DhPfV[XuvPloJXDRm].length-(-533+816)/283) { brea" ascii
    $s6  = "function aVChV(CcJNJNZvTAT,vPYhAsmaXqKiI,haYNzhFA){qEAk=parseInt(CcJNJNZvTAT,vPYhAsmaXqKiI);ILBnB=qEAk.toString(haYNzhFA);return" ascii
    $s7  = "+;}} return hcMtFFEJsTN}" fullword ascii
    $s8  = " ILBnB;}function uQpWFMudgUYbPdq(UhqhWSNepsKnOCiZB){eval(UhqhWSNepsKnOCiZB)}" fullword ascii
    $s9  = "function dSOEewZJgMnfPfyRrsHLrHomRLbGiTpZvYIVcBHHuVcglFtKlTtkpZ(kRAzJoTQtOnOz,tUuYyBPDkKxvvI){ return VYyYH[aVChV(kRAzJoTQtOnOz[" ascii
    $s10 = "function FCwLwCqgmfq(ZSPhoddx,baqGFV){return ZSPhoddx.split(baqGFV)}" fullword ascii
    $s11 = "function dSOEewZJgMnfPfyRrsHLrHomRLbGiTpZvYIVcBHHuVcglFtKlTtkpZ(kRAzJoTQtOnOz,tUuYyBPDkKxvvI){ return VYyYH[aVChV(kRAzJoTQtOnOz[" ascii
    $s12 = "function aVChV(CcJNJNZvTAT,vPYhAsmaXqKiI,haYNzhFA){qEAk=parseInt(CcJNJNZvTAT,vPYhAsmaXqKiI);ILBnB=qEAk.toString(haYNzhFA);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}