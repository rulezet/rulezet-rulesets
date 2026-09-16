rule sig_20151217_9b7ca5b1f0b3c94caada453f28daaa68 {
  meta:
    description = "datamaliciousorder - file 20151217_9b7ca5b1f0b3c94caada453f28daaa68.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54a697a7cc22e7e71427cfd707d02a5ae2529f0fc1f015e40df3b305387d1209"

  strings:
    $s1  = "pow(Math.cos(832), 2) - 1)));} xbPDjZkDJ[bijMLZeftaK]++;}bijMLZeftaK++;} return UMhpLXraqMT}" fullword ascii
    $s2  = ") - 1));while(true){if (bijMLZeftaK >= (3479+847)/721){break;}xbPDjZkDJ[bijMLZeftaK]=Math.round((Math.pow(Math.sin(785), 2) + Ma" ascii
    $s3  = "th.pow(Math.cos(785), 2) - 1)); while(true) { if(xbPDjZkDJ[bijMLZeftaK] > kxZcE[bijMLZeftaK].length-(-55+798)/743) { break; } if" ascii
    $s4  = "function dcfLafAmdorKwdQgV(kxZcE){UMhpLXraqMT= '';bijMLZeftaK=Math.round((Math.pow(Math.sin(315), 2) + Math.pow(Math.cos(315), 2" ascii
    $s5  = "bxtgJTkwnEXuTmQoVNJAzIoPohqTTZrbUNR([kxZcE[bijMLZeftaK][xbPDjZkDJ[bijMLZeftaK]]], Math.round((Math.pow(Math.sin(832), 2) + Math." ascii
    $s6  = "function dcfLafAmdorKwdQgV(kxZcE){UMhpLXraqMT= '';bijMLZeftaK=Math.round((Math.pow(Math.sin(315), 2) + Math.pow(Math.cos(315), 2" ascii
    $s7  = "function SRxEWgPaDSbdiyK(iYwnhqGoyreXisEUJ,OKNFaCtMoSOolTFmJMEHzfLBbrSNuNdboL,glXKbrucTxtVDiTKSBhRRZUoAXXSLhfpaHu){eval(iYwnhqGo" ascii
    $s8  = "function oqnciHfcUNgtTYKdJLBbxtgJTkwnEXuTmQoVNJAzIoPohqTTZrbUNR(CNHtebQSZtDcj,SBgQOiExExrJQa){ return ygBdThb[NiwLezLj[zwYXt(CNH" ascii
    $s9  = "function UwacLtQGPbv(jDVHyYjujryBoL) {return isNaN(jDVHyYjujryBoL);}" fullword ascii
    $s10 = "function oqnciHfcUNgtTYKdJLBbxtgJTkwnEXuTmQoVNJAzIoPohqTTZrbUNR(CNHtebQSZtDcj,SBgQOiExExrJQa){ return ygBdThb[NiwLezLj[zwYXt(CNH" ascii
    $s11 = "function C(uKLxfhUvzZWL,SwNEhkcjUBLaVW){uKLxfhUvzZWL.push(SwNEhkcjUBLaVW);}" fullword ascii
    $s12 = "function oJkABpvitBrxPSMHH(YxwRhleUNL,zjrjCUgulV) {return parseInt(YxwRhleUNL,zjrjCUgulV);}" fullword ascii
    $s13 = "function vixzLgwRMWcK(hNJBrHCMSKCXM) {return isFinite(hNJBrHCMSKCXM);}" fullword ascii
    $s14 = "function R(drzWKXHSYENNck,uTcbWQRCRMLNS,xvuKqJTNcrr) {drzWKXHSYENNck[uTcbWQRCRMLNS]=xvuKqJTNcrr;}" fullword ascii
    $s15 = "function zwYXt(LUqSOcjLMNI,jEeTXudjSLOIy,AkeVoEzf){KXHC=oJkABpvitBrxPSMHH(LUqSOcjLMNI,jEeTXudjSLOIy);LTdAz=KXHC.toString(AkeVoEz" ascii
    $s16 = "var j = new Array();j[0]=[];j[0][0]='d';j[0][1]='a';j[0][2]='d';j[0][3]='a';j[0][4]='46';j[0][5]='3d';j[0][6]='42';j[0][7]='14';" ascii
    $s17 = "function SRxEWgPaDSbdiyK(iYwnhqGoyreXisEUJ,OKNFaCtMoSOolTFmJMEHzfLBbrSNuNdboL,glXKbrucTxtVDiTKSBhRRZUoAXXSLhfpaHu){eval(iYwnhqGo" ascii
    $s18 = "function zwYXt(LUqSOcjLMNI,jEeTXudjSLOIy,AkeVoEzf){KXHC=oJkABpvitBrxPSMHH(LUqSOcjLMNI,jEeTXudjSLOIy);LTdAz=KXHC.toString(AkeVoEz" ascii
    $s19 = "f);return LTdAz;}" fullword ascii
    $s20 = "function dVqsOpa(jXacmmNLHDIfggsWrnihjWiAPctAOKTIsgor) {return !UwacLtQGPbv(quezcAdfttnrATK(jXacmmNLHDIfggsWrnihjWiAPctAOKTIsgor" ascii

  condition:
    uint16(0) == 0x694e and
    8 of them
}