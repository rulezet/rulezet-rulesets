rule sig_20151215_e4002e73618f9a452dcd51e827faeb52 {
  meta:
    description = "datamaliciousorder - file 20151215_e4002e73618f9a452dcd51e827faeb52.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "94d07e60c3fa8f4bd01c57fe719b29bc4680611942223869dd17390f4dde9f93"

  strings:
    $s1  = "ath.pow(Math.cos(922), 2) - 1)); while(true) { if(pIlHjNfjq[xxLTbivbyjd] > lGekn[xxLTbivbyjd].length-(-277+648)/371) { break; } " ascii
    $s2  = ".pow(Math.cos(583), 2) - 1)));} pIlHjNfjq[xxLTbivbyjd]++;}} return YzLkQWdycSt}" fullword ascii
    $s3  = "function INacxDkArmwNlNSti(lGekn){YzLkQWdycSt= N[1818];for(xxLTbivbyjd=Math.round((Math.pow(Math.sin(256), 2) + Math.pow(Math.co" ascii
    $s4  = "function INacxDkArmwNlNSti(lGekn){YzLkQWdycSt= N[1818];for(xxLTbivbyjd=Math.round((Math.pow(Math.sin(256), 2) + Math.pow(Math.co" ascii
    $s5  = "nhGqwSXFuiELviMoXRvBHaRuTpHUzodgCmxu([lGekn[xxLTbivbyjd][pIlHjNfjq[xxLTbivbyjd]]], Math.round((Math.pow(Math.sin(583), 2) + Math" ascii
    $s6  = "function aEgBzWT(IuhbCywzJwaEacMDnaJXvPqkZRxljvgAIPpr) {return !isNaN(parseFloat(IuhbCywzJwaEacMDnaJXvPqkZRxljvgAIPpr)) && isFin" ascii
    $s7  = "function aEgBzWT(IuhbCywzJwaEacMDnaJXvPqkZRxljvgAIPpr) {return !isNaN(parseFloat(IuhbCywzJwaEacMDnaJXvPqkZRxljvgAIPpr)) && isFin" ascii
    $s8  = "function x(oOhzdAwsNRuu,KlVbgsBoEaLxsK){oOhzdAwsNRuu.push(KlVbgsBoEaLxsK);}function K7(msQTyMjGlXiptONN){if(aEgBzWT(msQTyMjGlXip" ascii
    $s9  = "tONN)) {return (String.fromCharCode(msQTyMjGlXiptONN) + String.fromCharCode((8118+114)/196));}}" fullword ascii
    $s10 = "var N=new Array();" fullword ascii
    $s11 = "function mtfFZ(ElyuFhsneWX,dJSGRoLDELmxR,FDDBLcXS){DVrO=parseInt(ElyuFhsneWX,dJSGRoLDELmxR);LVIHl=DVrO.toString(FDDBLcXS);return" ascii
    $s12 = "function fKYLTaWiyhk(iWZTXFED,tULRGo){return iWZTXFED.split(tULRGo)}" fullword ascii
    $s13 = "function x(oOhzdAwsNRuu,KlVbgsBoEaLxsK){oOhzdAwsNRuu.push(KlVbgsBoEaLxsK);}function K7(msQTyMjGlXiptONN){if(aEgBzWT(msQTyMjGlXip" ascii
    $s14 = "function mtfFZ(ElyuFhsneWX,dJSGRoLDELmxR,FDDBLcXS){DVrO=parseInt(ElyuFhsneWX,dJSGRoLDELmxR);LVIHl=DVrO.toString(FDDBLcXS);return" ascii
    $s15 = "function zMMAqoVuCcdjseVPgMnhGqwSXFuiELviMoXRvBHaRuTpHUzodgCmxu(nZLgCnhCSlrLh,iSogGzbkrKimvy){ return BBXDgvq[JvoIttih[mtfFZ(nZL" ascii
    $s16 = "function zMMAqoVuCcdjseVPgMnhGqwSXFuiELviMoXRvBHaRuTpHUzodgCmxu(nZLgCnhCSlrLh,iSogGzbkrKimvy){ return BBXDgvq[JvoIttih[mtfFZ(nZL" ascii
    $s17 = "function DBMxzjtIdAeakpG(xytYZWobikFKJpoWa){eval(xytYZWobikFKJpoWa)}" fullword ascii
    $s18 = " LVIHl;}function DBMxzjtIdAeakpG(xytYZWobikFKJpoWa,hwRLhAqjCNsBPVhdSzVLluXJxFsJDHRvtW,xbysnoAHNBBoBXJYNqpeFSQqZknnnuLSKzz){eval(" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}