rule sig_20151209_76ee7af90fa472a672d2eaf8362a533e {
  meta:
    description = "datamaliciousorder - file 20151209_76ee7af90fa472a672d2eaf8362a533e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c753d1418c57fe3289bd4c532d1a38adbcb03bb1ce106b6f198bb249c1506f49"

  strings:
    $s1  = "function XDmgMdO(hEnHRhplBrGXNRjgAsnmOxCCsEfEFtAlFOaH) {return !isNaN(parseFloat(hEnHRhplBrGXNRjgAsnmOxCCsEfEFtAlFOaH)) && isFin" ascii
    $s2  = " ZbOwN;}function JwiXUTATTtJknWT(CmDpFTTqvHmOkLuMT){eval(CmDpFTTqvHmOkLuMT)}" fullword ascii
    $s3  = "function jTzfZ(FiinColhPao,ZVKgjENJNWLhD,JiROmeRM){fAGv=parseInt(FiinColhPao,ZVKgjENJNWLhD);ZbOwN=fAGv.toString(JiROmeRM);return" ascii
    $s4  = "function XDmgMdO(hEnHRhplBrGXNRjgAsnmOxCCsEfEFtAlFOaH) {return !isNaN(parseFloat(hEnHRhplBrGXNRjgAsnmOxCCsEfEFtAlFOaH)) && isFin" ascii
    $s5  = "function dXBSGlBUFwcwHQSBo(Lquti){mlkTJOdWJqW= '';for(wfIvITUsoHN=(-645+645)/152; wfIvITUsoHN < (691+371)/531; wfIvITUsoHN++) {H" ascii
    $s6  = "function wRbgCrPSMwDLvXGEXtRRbFhaDSHiinFLSTugeMhEHLWKITnHRAAeLZ(HsjFKqRcTDixI,bwWHiqoMdfnLEF){ return Etrer[jTzfZ(HsjFKqRcTDixI[" ascii
    $s7  = "function jTzfZ(FiinColhPao,ZVKgjENJNWLhD,JiROmeRM){fAGv=parseInt(FiinColhPao,ZVKgjENJNWLhD);ZbOwN=fAGv.toString(JiROmeRM);return" ascii
    $s8  = "function jHIBOLUTWDk(frFAaxQl,uffvSS){return frFAaxQl.split(uffvSS)}" fullword ascii
    $s9  = "} return mlkTJOdWJqW}" fullword ascii
    $s10 = "function dXBSGlBUFwcwHQSBo(Lquti){mlkTJOdWJqW= '';for(wfIvITUsoHN=(-645+645)/152; wfIvITUsoHN < (691+371)/531; wfIvITUsoHN++) {H" ascii
    $s11 = "function wRbgCrPSMwDLvXGEXtRRbFhaDSHiinFLSTugeMhEHLWKITnHRAAeLZ(HsjFKqRcTDixI,bwWHiqoMdfnLEF){ return Etrer[jTzfZ(HsjFKqRcTDixI[" ascii
    $s12 = "piLAFujF[wfIvITUsoHN]=(-114+114)/546; while(true) { if(HpiLAFujF[wfIvITUsoHN] > Lquti[wfIvITUsoHN].length-(-886+890)/4) { break;" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}