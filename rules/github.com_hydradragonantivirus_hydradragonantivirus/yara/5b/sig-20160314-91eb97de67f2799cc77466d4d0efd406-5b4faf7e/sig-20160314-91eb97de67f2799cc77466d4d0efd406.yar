rule sig_20160314_91eb97de67f2799cc77466d4d0efd406 {
  meta:
    description = "datamaliciousorder - file 20160314_91eb97de67f2799cc77466d4d0efd406.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a63bc9f2022271810ed9862e56f2e2f5fbc4f602bf67f77c6e83f4387a5bc46"

  strings:
    $s1  = "var fDSDpUo = \"Sc fWOAlBg r LDhzFchPV ipting rcyLFOY Bjp ile TEMPCJfUFgpTop System nA gszCK Obj NcsSRB ect EBnfRrN qNXGM\".spli" ascii
    $s2  = "var fDSDpUo = \"Sc fWOAlBg r LDhzFchPV ipting rcyLFOY Bjp ile TEMPCJfUFgpTop System nA gszCK Obj NcsSRB ect EBnfRrN qNXGM\".spli" ascii
    $s3  = "var FR = true  , epRj = Kff[7] + Kff[9] + Kff[11];" fullword ascii
    $s4  = "return fDSDpUo[0] + fDSDpUo[2] + fDSDpUo[4] + \".F\" + fDSDpUo[7] + fDSDpUo[9] + fDSDpUo[12] + fDSDpUo[14];" fullword ascii
    $s5  = "var Kff = (\"2.XMLHTTP fjPiweV rNHsV XML ream St twcUNkAQ AD hbAPMsq O gRci D\").split(\" \");" fullword ascii
    $s6  = "blsZN.open(HLyJM,yOvNC,false);" fullword ascii
    $s7  = "kXL = I; break; " fullword ascii
    $s8  = "function EVqnC(yDsuSM) {" fullword ascii
    $s9  = "function aYuR(jaEdp) {" fullword ascii
    $s10 = "if(I>=f.length) {break;}" fullword ascii
    $s11 = "return VSLv.ExpandEnvironmentStrings(aRirq);" fullword ascii
    $s12 = "function oEGm(eivUh) {" fullword ascii
    $s13 = "if (lOFOy == 1002-802){return true;} else {return false;}" fullword ascii
    $s14 = "function WpKF(CvpSU) {" fullword ascii
    $s15 = "function RPfz(blsZN,yOvNC,HLyJM) {" fullword ascii
    $s16 = "return new ActiveXObject(yDsuSM);" fullword ascii
    $s17 = "return TLGd.responseBody;" fullword ascii
    $s18 = "if (jaEdp > 186903-689){return true;} else {return false;}" fullword ascii
    $s19 = "function bhrv(VUSII) {" fullword ascii
    $s20 = "if (R >= eivUh.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}