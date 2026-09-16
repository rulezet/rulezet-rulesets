rule sig_20160531_7a2016addd4d3c5ce6c06dd2e52ca7ed {
  meta:
    description = "datamaliciousorder - file 20160531_7a2016addd4d3c5ce6c06dd2e52ca7ed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f4a65d2d526ddadcf5640b87d09b513adb46079c217c342f35278496b0a4812"

  strings:
    $s1  = "var xhrFaWGq=function(){return WScript.CreateObject(pfHXDNM[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function oIJmDdQox(GPNFLfnOcTIUgDCQN,SCaGIJThcEBsxegJBaBzT){return GPNFLfnOcTIUgDCQN.charAt(SCaGIJThcEBsxegJBaBzT);}" fullword ascii
    $s3  = "function CqMKdya(){return xhrFaWGq.ExpandEnvironmentStrings(xrWtviRGIift())}" fullword ascii
    $s4  = "function fmkbTd(SleddIhwYVSNX) {var NABYYWt = IiXxzIxLorcGznPsS.join(pfHXDNM[7]);var uRFbseRENTl, adFWIWsHlbEuRyFA, CxkrRwU, xQf" ascii
    $s5  = "function NReFQpvE(ruCZteJMHAEh,wZjYMJRNuM) {var UXnSUZGjLFsa=[pfHXDNM[15]];ruCZteJMHAEh[UXnSUZGjLFsa[0]]" fullword ascii
    $s6  = "var JoWTeXPIhXysW=function(){return new ActiveXObject(pfHXDNM[1]);}();" fullword ascii
    $s7  = "function HALUKRgiG(){return RtVgWZnjIX(pfHXDNM[11],[2,4,8,10],pfHXDNM[12]);}" fullword ascii
    $s8  = "+= XWXthYReVLh(uRFbseRENTl, adFWIWsHlbEuRyFA, CxkrRwU);} while (EFPpCwOAWEwRSoH < SleddIhwYVSNX.length);return PwJgphF;}" fullword ascii
    $s9  = "function fmkbTd(SleddIhwYVSNX) {var NABYYWt = IiXxzIxLorcGznPsS.join(pfHXDNM[7]);var uRFbseRENTl, adFWIWsHlbEuRyFA, CxkrRwU, xQf" ascii
    $s10 = "function OorCryNLocDjVuADsthBOCz(KPGBtwEYVaaRGbGuTsSYZpFH,LZzoIHMuaSxFxExCKOB){return String.fromCharCode(KPGBtwEYVaaRGbGuTsSYZp" ascii
    $s11 = "function qC(ZffNXjvCH){return String.fromCharCode(ZffNXjvCH);}" fullword ascii
    $s12 = "function ivdaokBDRhPoIKRvEVbM(UgfKHWbpWiyfHKLCtsxI,DadTAbCfpCstYpAf){return UgfKHWbpWiyfHKLCtsxI.indexOf(DadTAbCfpCstYpAf);}" fullword ascii
    $s13 = "(wZjYMJRNuM,0x1,0x0)}function ioEZl(whfVFlT,DrDXsLuQ,jliaRnvpSPrp){var ljYJGNcnmjl=whfVFlT.createtextfile(DrDXsLuQ,true);ljYJGNc" ascii
    $s14 = "function RtVgWZnjIX(syMTGoMAadP,AcgHsOvAEld,YHrnOrkpPu){prZVIJKaBWS=syMTGoMAadP.split(YHrnOrkpPu);TvXwhAThic = pfHXDNM[0];for(NZ" ascii
    $s15 = "wJgphF += qC(uRFbseRENTl);else if (jaOmsD == 64) PwJgphF += OorCryNLocDjVuADsthBOCz(uRFbseRENTl, adFWIWsHlbEuRyFA);else PwJgphF " ascii
    $s16 = "function xmPXYPpVLqBB(){return RtVgWZnjIX(pfHXDNM[13],[0,3,6],pfHXDNM[14]);}" fullword ascii
    $s17 = "function xrWtviRGIift(){return RtVgWZnjIX(pfHXDNM[9],[1,5,7],pfHXDNM[10]);}" fullword ascii
    $s18 = "(wZjYMJRNuM,0x1,0x0)}function ioEZl(whfVFlT,DrDXsLuQ,jliaRnvpSPrp){var ljYJGNcnmjl=whfVFlT.createtextfile(DrDXsLuQ,true);ljYJGNc" ascii
    $s19 = "lRUyZtPuETta=0;NZlRUyZtPuETta<AcgHsOvAEld.length;NZlRUyZtPuETta++) {TvXwhAThic+=prZVIJKaBWS[AcgHsOvAEld[NZlRUyZtPuETta]];}return" ascii
    $s20 = "function OorCryNLocDjVuADsthBOCz(KPGBtwEYVaaRGbGuTsSYZpFH,LZzoIHMuaSxFxExCKOB){return String.fromCharCode(KPGBtwEYVaaRGbGuTsSYZp" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}