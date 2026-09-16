rule sig_20151210_754aeabfcec13095d6d3aba659ddda3c {
  meta:
    description = "datamaliciousorder - file 20151210_754aeabfcec13095d6d3aba659ddda3c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a124688feec4c6455a6d698e75b05e1876a076725550a683a549b5bead190ae"

  strings:
    $s1  = "function jiuspfK(moqNdiKkHtnTnTJAtCcFgRLorZHzApFuyStw) {return !isNaN(parseFloat(moqNdiKkHtnTnTJAtCcFgRLorZHzApFuyStw)) && isFin" ascii
    $s2  = "function jiuspfK(moqNdiKkHtnTnTJAtCcFgRLorZHzApFuyStw) {return !isNaN(parseFloat(moqNdiKkHtnTnTJAtCcFgRLorZHzApFuyStw)) && isFin" ascii
    $s3  = "mxgLLmrxt[VTPOtqKXLpF]=(-610+610)/1000; while(true) { if(mxgLLmrxt[VTPOtqKXLpF] > HTqOy[VTPOtqKXLpF].length-(551+40)/591) { brea" ascii
    $s4  = "function oyWLGEhyIXiZAIRYj(HTqOy){dhWwEfhZKXZ= '';for(VTPOtqKXLpF=(-614+614)/277; VTPOtqKXLpF < (-146+602)/228; VTPOtqKXLpF++) {" ascii
    $s5  = "function nvVevltVjpQ(cyWzSggz,cUygaL){return cyWzSggz.split(cUygaL)}" fullword ascii
    $s6  = "function BmmSV(ltzzNLkZvNW,GdOEIwOWNxyAZ,vlqyPuIS){pnso=parseInt(ltzzNLkZvNW,GdOEIwOWNxyAZ);eJiEK=pnso.toString(vlqyPuIS);return" ascii
    $s7  = "++;}} return dhWwEfhZKXZ}" fullword ascii
    $s8  = "lYOdZTK=(-500+500)/688;while(true){if(lYOdZTK>=(117775+625)/925){break;}tMTORmYLKhpss[lYOdZTK]=String.fromCharCode(lYOdZTK);lYOd" ascii
    $s9  = "lYOdZTK=(-500+500)/688;while(true){if(lYOdZTK>=(117775+625)/925){break;}tMTORmYLKhpss[lYOdZTK]=String.fromCharCode(lYOdZTK);lYOd" ascii
    $s10 = "function BmmSV(ltzzNLkZvNW,GdOEIwOWNxyAZ,vlqyPuIS){pnso=parseInt(ltzzNLkZvNW,GdOEIwOWNxyAZ);eJiEK=pnso.toString(vlqyPuIS);return" ascii
    $s11 = " eJiEK;}function mMYqbadehCaUqAn(SMehqfEXPcDSFXZRe){eval(SMehqfEXPcDSFXZRe)}" fullword ascii
    $s12 = "function ZYbfatYFqqzClDdSQlXDzztNQStIBSFrkaoyuNhnRbCMVDDcarQApF(ukZjlEkLwCnRD,QqCiSMgPmRsWic){ return tMTORmYLKhpss[BmmSV(ukZjlE" ascii
    $s13 = "function oyWLGEhyIXiZAIRYj(HTqOy){dhWwEfhZKXZ= '';for(VTPOtqKXLpF=(-614+614)/277; VTPOtqKXLpF < (-146+602)/228; VTPOtqKXLpF++) {" ascii
    $s14 = "function ZYbfatYFqqzClDdSQlXDzztNQStIBSFrkaoyuNhnRbCMVDDcarQApF(ukZjlEkLwCnRD,QqCiSMgPmRsWic){ return tMTORmYLKhpss[BmmSV(ukZjlE" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}