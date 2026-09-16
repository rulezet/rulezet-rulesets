rule sig_20160531_59afac8e3340b831bde6f20bc7e73c17 {
  meta:
    description = "datamaliciousorder - file 20160531_59afac8e3340b831bde6f20bc7e73c17.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1633b289f7d6cc9b76e14de6e1ce8551c6aa8f87cee791f5b308a9ab82587449"

  strings:
    $s1  = "function ejsShegdfBlDqXwNbcpZ(mxibyFSChOStdRRX,JdvmRxFBBKSWLmXosYRfV){return mxibyFSChOStdRRX.charAt(JdvmRxFBBKSWLmXosYRfV);}" fullword ascii
    $s2  = "var aqzkpTt=function(){return WScript.CreateObject(FTDwkqnpIXiel[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s3  = "function hxJrbOaqg(MICXvnwVTEd,GuITQmcpracLwDCoKPIB){return String.fromCharCode(MICXvnwVTEd,GuITQmcpracLwDCoKPIB);}" fullword ascii
    $s4  = "function koWvCYDigzslp(YKEMFnXHWPIQqjBlXJJn,ODZrwZuAW,udnpH){return String.fromCharCode(YKEMFnXHWPIQqjBlXJJn,ODZrwZuAW,udnpH);}" fullword ascii
    $s5  = ", vGzRNSWtwkbXPzOtwycset);} while (loOUBIBuOXFvxAU < wONrWmJEvHrAB.length);return phFeBJanv;}" fullword ascii
    $s6  = "(StXfmXkxPpty,0x1,0x0)}function MuXRFgIdWRXITJ(eFHDCPpLj,SVZmQZyhVsOD,qTqHZLS){var iPhJRAggDoZm=eFHDCPpLj.createtextfile(SVZmQZy" ascii
    $s7  = "hVsOD,true);iPhJRAggDoZm.WriteLine(qTqHZLS);iPhJRAggDoZm.Close();}" fullword ascii
    $s8  = "r(NHaLJNuZ=0;NHaLJNuZ<kLMKg.length;NHaLJNuZ++) {dHSngIMvydVMA+=rKdIk[kLMKg[NHaLJNuZ]];}return dHSngIMvydVMA.substring(3,dHSngIMv" ascii
    $s9  = "function aUmnKkie(EANCtgZVYiCgH,StXfmXkxPpty) {var gXKnOixTPiSly=[FTDwkqnpIXiel[15]];EANCtgZVYiCgH[gXKnOixTPiSly[0]]" fullword ascii
    $s10 = "function SdLSdbFLkJe(tfkUXTSXvP,kLMKg,eblaxRNGpkAqHv){rKdIk=tfkUXTSXvP.split(eblaxRNGpkAqHv);dHSngIMvydVMA = FTDwkqnpIXiel[0];fo" ascii
    $s11 = "var wCqwfpK=function(){return new ActiveXObject(FTDwkqnpIXiel[1]);}();" fullword ascii
    $s12 = "XfSoTPiBBGMBvs>> 8 & 0xff;vGzRNSWtwkbXPzOtwycset = KmqrlXfSoTPiBBGMBvs & 0xff;if (hhSaqh == 64) phFeBJanv += LS(OQpiUhl);else if" ascii
    $s13 = "function cZGEamX(){return SdLSdbFLkJe(FTDwkqnpIXiel[13],[0,3,6],FTDwkqnpIXiel[14]);}" fullword ascii
    $s14 = "function SvcRukQjmQgn(){return aqzkpTt.ExpandEnvironmentStrings(DtjVIhm())}" fullword ascii
    $s15 = "function ZIxOIhxgLDotNuF(IDfFvShgwTf,uvuMmMSw){return IDfFvShgwTf.indexOf(uvuMmMSw);}" fullword ascii
    $s16 = "function LS(odxdUyipvdYDOoIkNbO){return String.fromCharCode(odxdUyipvdYDOoIkNbO);}" fullword ascii
    $s17 = "function DtjVIhm(){return SdLSdbFLkJe(FTDwkqnpIXiel[9],[1,5,7],FTDwkqnpIXiel[10]);}" fullword ascii
    $s18 = "(StXfmXkxPpty,0x1,0x0)}function MuXRFgIdWRXITJ(eFHDCPpLj,SVZmQZyhVsOD,qTqHZLS){var iPhJRAggDoZm=eFHDCPpLj.createtextfile(SVZmQZy" ascii
    $s19 = "function jPDPbhPDuyfFuX(){return SdLSdbFLkJe(FTDwkqnpIXiel[11],[2,4,8,10],FTDwkqnpIXiel[12]);}" fullword ascii
    $s20 = "function SdLSdbFLkJe(tfkUXTSXvP,kLMKg,eblaxRNGpkAqHv){rKdIk=tfkUXTSXvP.split(eblaxRNGpkAqHv);dHSngIMvydVMA = FTDwkqnpIXiel[0];fo" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}