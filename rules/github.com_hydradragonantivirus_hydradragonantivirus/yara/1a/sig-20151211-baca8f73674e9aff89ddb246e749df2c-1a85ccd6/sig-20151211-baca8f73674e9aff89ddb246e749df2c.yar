rule sig_20151211_baca8f73674e9aff89ddb246e749df2c {
  meta:
    description = "datamaliciousorder - file 20151211_baca8f73674e9aff89ddb246e749df2c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d9c713789da9408b1f9bce25fd48118a3c6dfeab5d450974511330762e2c739"

  strings:
    $s1  = "function JRRDlLActvfUqmRXYmtINfSMFueKTOeLYlAIbwuVicNfzpVYvnIIYN(ulpSesxzwPnop,KqgUGqParRzulA){ return jTWQU[cDWxP(ulpSesxzwPnop[" ascii
    $s2  = "function JRRDlLActvfUqmRXYmtINfSMFueKTOeLYlAIbwuVicNfzpVYvnIIYN(ulpSesxzwPnop,KqgUGqParRzulA){ return jTWQU[cDWxP(ulpSesxzwPnop[" ascii
    $s3  = "function vOGpkNawHuHvhGgAM(ygBcp){JvDsBVwThtM= '';WSvKBBQeera=(-128+128)/971; while(true){if(WSvKBBQeera >= (262+968)/615)break;" ascii
    $s4  = "function icrEZDn(OoNGlZMjskQueWSEprqdFhaDhgqKSnGbOApS) {return !isNaN(parseFloat(OoNGlZMjskQueWSEprqdFhaDhgqKSnGbOApS)) && isFin" ascii
    $s5  = "function icrEZDn(OoNGlZMjskQueWSEprqdFhaDhgqKSnGbOApS) {return !isNaN(parseFloat(OoNGlZMjskQueWSEprqdFhaDhgqKSnGbOApS)) && isFin" ascii
    $s6  = "function vOGpkNawHuHvhGgAM(ygBcp){JvDsBVwThtM= '';WSvKBBQeera=(-128+128)/971; while(true){if(WSvKBBQeera >= (262+968)/615)break;" ascii
    $s7  = "var f=new Array(\"29\",\"2f\",\"2a\",\"27\",\"2d\",\"29\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s8  = "var C=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"34\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s9  = "uJcEwLEMn[WSvKBBQeera]=(-255+255)/564; while(true) { if(uJcEwLEMn[WSvKBBQeera] > ygBcp[WSvKBBQeera].length-(-115+569)/454) { bre" ascii
    $s10 = "function cDWxP(ckRNxKvbYHe,bRmZaVkqfJaZP,TterMIAR){ueCt=parseInt(ckRNxKvbYHe,bRmZaVkqfJaZP);SFVVf=ueCt.toString(TterMIAR);return" ascii
    $s11 = " SFVVf;}function WVdhhxTFSAjGFTq(ByFxgPqrtoEsJHgAX){eval(ByFxgPqrtoEsJHgAX)}" fullword ascii
    $s12 = "var f=new Array(\"29\",\"2f\",\"2a\",\"27\",\"2d\",\"29\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s13 = "var C=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"34\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s14 = "]++;}WSvKBBQeera++;} return JvDsBVwThtM}" fullword ascii
    $s15 = "function cDWxP(ckRNxKvbYHe,bRmZaVkqfJaZP,TterMIAR){ueCt=parseInt(ckRNxKvbYHe,bRmZaVkqfJaZP);SFVVf=ueCt.toString(TterMIAR);return" ascii
    $s16 = "function LLpIoOruvQO(yzFNvHoC,pvCikV){return yzFNvHoC.split(pvCikV)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}