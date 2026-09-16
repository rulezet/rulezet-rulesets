rule sig_20151214_37582ff94dd78f37c3c1523b39e642b4 {
  meta:
    description = "datamaliciousorder - file 20151214_37582ff94dd78f37c3c1523b39e642b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ae2967411bc5ad38b84437559476c53f09d156921077bdd713d9754a3afb5b6"

  strings:
    $s1  = "(Math.cos(75), 2) - 1)));} AhXSrwPEd[xLthBkuFVrk]++;}} return rinmWdLHTmd}" fullword ascii
    $s2  = "function wohGrLfHLPwPOApgG(zDdHu){rinmWdLHTmd= L[1783];for(xLthBkuFVrk=Math.round((Math.pow(Math.sin(89), 2) + Math.pow(Math.cos" ascii
    $s3  = "h.pow(Math.cos(426), 2) - 1)); while(true) { if(AhXSrwPEd[xLthBkuFVrk] > zDdHu[xLthBkuFVrk].length-(-323+371)/48) { break; } if " ascii
    $s4  = "function wohGrLfHLPwPOApgG(zDdHu){rinmWdLHTmd= L[1783];for(xLthBkuFVrk=Math.round((Math.pow(Math.sin(89), 2) + Math.pow(Math.cos" ascii
    $s5  = "function J(yUQqgmBkMUDY,fCDUbDFNpLrulB){yUQqgmBkMUDY.push(fCDUbDFNpLrulB);}function g3(KpuxzFBkaouNeMta){if(kSsJgCf(KpuxzFBkaouN" ascii
    $s6  = "eMta)) {return (String.fromCharCode(KpuxzFBkaouNeMta) + String.fromCharCode((37548+832)/505));}}" fullword ascii
    $s7  = "function kSsJgCf(CWHkMYqVKdPrKnJppAHAwddHutJcRpKkWYAs) {return !isNaN(parseFloat(CWHkMYqVKdPrKnJppAHAwddHutJcRpKkWYAs)) && isFin" ascii
    $s8  = "function kSsJgCf(CWHkMYqVKdPrKnJppAHAwddHutJcRpKkWYAs) {return !isNaN(parseFloat(CWHkMYqVKdPrKnJppAHAwddHutJcRpKkWYAs)) && isFin" ascii
    $s9  = "function TYguPVfQfMvvytDGWpvaXVKLoVKYvgtBFwjgpSKRmtUTBcrBDlVkyw(PxAjHQsHWPubp,xRlOrRKmqiYoJl){ return AzgjSRS[OmQIhIYJ[qPxRn(PxA" ascii
    $s10 = "function TYguPVfQfMvvytDGWpvaXVKLoVKYvgtBFwjgpSKRmtUTBcrBDlVkyw(PxAjHQsHWPubp,xRlOrRKmqiYoJl){ return AzgjSRS[OmQIhIYJ[qPxRn(PxA" ascii
    $s11 = "var L=new Array();" fullword ascii
    $s12 = "function bumjaxaxEhY(dgqfnFhJ,lUyKNr){return dgqfnFhJ.split(lUyKNr)}" fullword ascii
    $s13 = "function J(yUQqgmBkMUDY,fCDUbDFNpLrulB){yUQqgmBkMUDY.push(fCDUbDFNpLrulB);}function g3(KpuxzFBkaouNeMta){if(kSsJgCf(KpuxzFBkaouN" ascii
    $s14 = "function PKTKKXkxsuQrGqP(HTDXtEZahcbHVbdUT){eval(HTDXtEZahcbHVbdUT)}" fullword ascii
    $s15 = " qMqBJ;}function PKTKKXkxsuQrGqP(HTDXtEZahcbHVbdUT,DmyukNDpTqHyyzGdXDGtzQvminrTDSSBMO,BfysqkEhjgyRrsVMEZRFrbizgEzKEBvgdnh){eval(" ascii
    $s16 = "function qPxRn(OyfoKGcJJMZ,DJvhcaPkfIznR,aGYkxxON){wpdh=parseInt(OyfoKGcJJMZ,DJvhcaPkfIznR);qMqBJ=wpdh.toString(aGYkxxON);return" ascii
    $s17 = "function qPxRn(OyfoKGcJJMZ,DJvhcaPkfIznR,aGYkxxON){wpdh=parseInt(OyfoKGcJJMZ,DJvhcaPkfIznR);qMqBJ=wpdh.toString(aGYkxxON);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}