rule sig_20151215_5f4bd946b9efedbf5651627f1fa43ca2 {
  meta:
    description = "datamaliciousorder - file 20151215_5f4bd946b9efedbf5651627f1fa43ca2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6185b1bd0b0515a87327c741b072cadb4f4dfe71dc336103445e0bc59c923531"

  strings:
    $s1  = "ath.pow(Math.cos(611), 2) - 1)); while(true) { if(OfBVbGBVM[MjkkLFHCATk] > uhnph[MjkkLFHCATk].length-(-267+811)/544) { break; } " ascii
    $s2  = "function jIGJFss(UOpHHMaSPzIWIevfTpxuTfbsHepxyDNUpCMi) {return !isNaN(parseFloat(UOpHHMaSPzIWIevfTpxuTfbsHepxyDNUpCMi)) && isFin" ascii
    $s3  = "function jIGJFss(UOpHHMaSPzIWIevfTpxuTfbsHepxyDNUpCMi) {return !isNaN(parseFloat(UOpHHMaSPzIWIevfTpxuTfbsHepxyDNUpCMi)) && isFin" ascii
    $s4  = "function ipHXOywuaCPXkbqFq(uhnph){fzumoGseXpH= D[1764];for(MjkkLFHCATk=Math.round((Math.pow(Math.sin(477), 2) + Math.pow(Math.co" ascii
    $s5  = "w(Math.cos(128), 2) - 1)));} OfBVbGBVM[MjkkLFHCATk]++;}} return fzumoGseXpH}" fullword ascii
    $s6  = "aFQs)) {return (String.fromCharCode(NEaiKjyottcoaFQs) + String.fromCharCode((55381+433)/946));}}" fullword ascii
    $s7  = "function ipHXOywuaCPXkbqFq(uhnph){fzumoGseXpH= D[1764];for(MjkkLFHCATk=Math.round((Math.pow(Math.sin(477), 2) + Math.pow(Math.co" ascii
    $s8  = " aDfpO;}function ZrgToVXAlwsAGKx(oPEnEYCLPiUclWcuE,OlRFRKMjwBdCsHLCFcuBmeUUwNzGXeDlbw,FqBlbllgtyJroPKUsggZFVesAGYrBVVveoR){eval(" ascii
    $s9  = "function dwSHq(BYMtFLqADtG,SMzphIKPPkXeS,yqHdyCiN){AMTs=parseInt(BYMtFLqADtG,SMzphIKPPkXeS);aDfpO=AMTs.toString(yqHdyCiN);return" ascii
    $s10 = "function ZrgToVXAlwsAGKx(oPEnEYCLPiUclWcuE){eval(oPEnEYCLPiUclWcuE)}" fullword ascii
    $s11 = "function dwSHq(BYMtFLqADtG,SMzphIKPPkXeS,yqHdyCiN){AMTs=parseInt(BYMtFLqADtG,SMzphIKPPkXeS);aDfpO=AMTs.toString(yqHdyCiN);return" ascii
    $s12 = "function EQdVoTgnKUd(UlJVnIoa,idRTGO){return UlJVnIoa.split(idRTGO)}" fullword ascii
    $s13 = "function bfklNYmgbTOFfGKivdOUrkhwEuUchakMuHHDBvkYhnvPBeByZsbLTW(HKeaWNQzRsEAg,fOSblFioTgJpyq){ return iUQmxuE[PkbgOnbz[dwSHq(HKe" ascii
    $s14 = "function bfklNYmgbTOFfGKivdOUrkhwEuUchakMuHHDBvkYhnvPBeByZsbLTW(HKeaWNQzRsEAg,fOSblFioTgJpyq){ return iUQmxuE[PkbgOnbz[dwSHq(HKe" ascii
    $s15 = "function U(jkbRKwqCARSy,xXBgUsCDMnAMsQ){jkbRKwqCARSy.push(xXBgUsCDMnAMsQ);}function W2(NEaiKjyottcoaFQs){if(jIGJFss(NEaiKjyottco" ascii
    $s16 = "function U(jkbRKwqCARSy,xXBgUsCDMnAMsQ){jkbRKwqCARSy.push(xXBgUsCDMnAMsQ);}function W2(NEaiKjyottcoaFQs){if(jIGJFss(NEaiKjyottco" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}