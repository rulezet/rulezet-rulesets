rule sig_20151210_546d95281e12b0da146bfdda2bd21220 {
  meta:
    description = "datamaliciousorder - file 20151210_546d95281e12b0da146bfdda2bd21220.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3f3413cfc7a5e15412f971be31edd7998d3bae1ba0790d584b320d295b0b0e2"

  strings:
    $s1  = "function zTLUDJQ(sMfHfphjGlkXLmuFlTFVrXmxrELljEeNEhRU) {return !isNaN(parseFloat(sMfHfphjGlkXLmuFlTFVrXmxrELljEeNEhRU)) && isFin" ascii
    $s2  = "function zTLUDJQ(sMfHfphjGlkXLmuFlTFVrXmxrELljEeNEhRU) {return !isNaN(parseFloat(sMfHfphjGlkXLmuFlTFVrXmxrELljEeNEhRU)) && isFin" ascii
    $s3  = "} return STFlMZMQAgY}" fullword ascii
    $s4  = "function bbnod(RpETlzZCkcF,qcDwEVRnWJxzj,GwcxWIet){CVZR=parseInt(RpETlzZCkcF,qcDwEVRnWJxzj);cihwg=CVZR.toString(GwcxWIet);return" ascii
    $s5  = "function lORpxJAtAtK(XRqECCDT,jDMBsO){return XRqECCDT.split(jDMBsO)}" fullword ascii
    $s6  = "jrdENCu=(-242+242)/660;while(true){if(jrdENCu>=(47727+529)/377){break;}bGZbutVpVOIfI[jrdENCu]=String.fromCharCode(jrdENCu);jrdEN" ascii
    $s7  = "function bFodIaFWKuWaRahHtVimbhUHKgTmTPESpdlwuHlJGgswAyAVTxHtbh(LsThgGXBwWwFB,paVdoDkRBUighR){ return bGZbutVpVOIfI[bbnod(LsThgG" ascii
    $s8  = "jrdENCu=(-242+242)/660;while(true){if(jrdENCu>=(47727+529)/377){break;}bGZbutVpVOIfI[jrdENCu]=String.fromCharCode(jrdENCu);jrdEN" ascii
    $s9  = "function PYcUdqjCPAYucwYyc(fcKBn){STFlMZMQAgY= '';for(dUMKsqlUONr=(-732+732)/913; dUMKsqlUONr < (-326+386)/30; dUMKsqlUONr++) {w" ascii
    $s10 = " cihwg;}function ZdMZgavMhBQhUBY(gpFqmyvyFEGedixwZ){eval(gpFqmyvyFEGedixwZ)}" fullword ascii
    $s11 = "function bbnod(RpETlzZCkcF,qcDwEVRnWJxzj,GwcxWIet){CVZR=parseInt(RpETlzZCkcF,qcDwEVRnWJxzj);cihwg=CVZR.toString(GwcxWIet);return" ascii
    $s12 = "function bFodIaFWKuWaRahHtVimbhUHKgTmTPESpdlwuHlJGgswAyAVTxHtbh(LsThgGXBwWwFB,paVdoDkRBUighR){ return bGZbutVpVOIfI[bbnod(LsThgG" ascii
    $s13 = "function PYcUdqjCPAYucwYyc(fcKBn){STFlMZMQAgY= '';for(dUMKsqlUONr=(-732+732)/913; dUMKsqlUONr < (-326+386)/30; dUMKsqlUONr++) {w" ascii
    $s14 = "VCzPuJVl[dUMKsqlUONr]=(-500+500)/171; while(true) { if(wVCzPuJVl[dUMKsqlUONr] > fcKBn[dUMKsqlUONr].length-(684+66)/750) { break;" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}