rule sig_20151210_8f8583d7f5cf476d185446edfaf8f113 {
  meta:
    description = "datamaliciousorder - file 20151210_8f8583d7f5cf476d185446edfaf8f113.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bbaad0b42d9095d84dd78574ce07ebc5441f9b2bf7a21d57c0f9c76564c4528"

  strings:
    $s1  = "function jAewqRX(kplYMrdJGRjsGGoCPawuXsqIbdsulfotFfUQ) {return !isNaN(parseFloat(kplYMrdJGRjsGGoCPawuXsqIbdsulfotFfUQ)) && isFin" ascii
    $s2  = "function jAewqRX(kplYMrdJGRjsGGoCPawuXsqIbdsulfotFfUQ) {return !isNaN(parseFloat(kplYMrdJGRjsGGoCPawuXsqIbdsulfotFfUQ)) && isFin" ascii
    $s3  = "+;}} return nRLeZHdXvRj}" fullword ascii
    $s4  = "function NGbxK(oGhulCvvGCi,wNQnDSInCWeEY,vCyNbecb){WCnk=parseInt(oGhulCvvGCi,wNQnDSInCWeEY);WuuFC=WCnk.toString(vCyNbecb);return" ascii
    $s5  = "cWYJXvj=(-217+217)/869;while(true){if(cWYJXvj>=(63500+372)/499){break;}OewfEFWFpehOF[cWYJXvj]=String.fromCharCode(cWYJXvj);cWYJX" ascii
    $s6  = "function UWcEcHGVuvS(xbymBAZk,yCIIXP){return xbymBAZk.split(yCIIXP)}" fullword ascii
    $s7  = "function xqLBvrfoLEvRGpIbmtoNbWLBMLlJMbWTlLHdqEPHMRfzGQWlePdqQb(yKJlVDlJnWwFp,eMnQdFUDjuzUsT){ return OewfEFWFpehOF[NGbxK(yKJlVD" ascii
    $s8  = "BbDYdSWi[GqGfqADTWLD]=(-592+592)/424; while(true) { if(IBbDYdSWi[GqGfqADTWLD] > KbeLh[GqGfqADTWLD].length-(131+298)/429) { break" ascii
    $s9  = " WuuFC;}function qksumQmLjyYsATV(qCYINAHcsEgyNaAHU){eval(qCYINAHcsEgyNaAHU)}" fullword ascii
    $s10 = "function xqLBvrfoLEvRGpIbmtoNbWLBMLlJMbWTlLHdqEPHMRfzGQWlePdqQb(yKJlVDlJnWwFp,eMnQdFUDjuzUsT){ return OewfEFWFpehOF[NGbxK(yKJlVD" ascii
    $s11 = "function uqRtFdYCjJsENpWen(KbeLh){nRLeZHdXvRj= '';for(GqGfqADTWLD=(-344+344)/54; GqGfqADTWLD < (-285+861)/288; GqGfqADTWLD++) {I" ascii
    $s12 = "cWYJXvj=(-217+217)/869;while(true){if(cWYJXvj>=(63500+372)/499){break;}OewfEFWFpehOF[cWYJXvj]=String.fromCharCode(cWYJXvj);cWYJX" ascii
    $s13 = "function uqRtFdYCjJsENpWen(KbeLh){nRLeZHdXvRj= '';for(GqGfqADTWLD=(-344+344)/54; GqGfqADTWLD < (-285+861)/288; GqGfqADTWLD++) {I" ascii
    $s14 = "function NGbxK(oGhulCvvGCi,wNQnDSInCWeEY,vCyNbecb){WCnk=parseInt(oGhulCvvGCi,wNQnDSInCWeEY);WuuFC=WCnk.toString(vCyNbecb);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}