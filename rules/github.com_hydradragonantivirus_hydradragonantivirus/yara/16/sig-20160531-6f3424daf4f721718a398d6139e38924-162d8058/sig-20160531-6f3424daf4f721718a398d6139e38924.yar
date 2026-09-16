rule sig_20160531_6f3424daf4f721718a398d6139e38924 {
  meta:
    description = "datamaliciousorder - file 20160531_6f3424daf4f721718a398d6139e38924.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb6ca85faf7e1fa7aee7fdb8b8f0655ec4879adfad5c8ecb31a426e18b3f3caa"

  strings:
    $s1  = "var EwCPcmVn=function(){return WScript.CreateObject(WGGBCSqpyusotXjMsleWmP[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function VbouinVjpRSYjwRyFPLrAQ(TWHftWAEOoxUzydP,uCJlCPcYXMJPQySnyNEj){return TWHftWAEOoxUzydP.charAt(uCJlCPcYXMJPQySnyNEj);}" fullword ascii
    $s3  = "GkCPqsfPYDpeJEB += esIImMQVsIwAZ(viPKkCTbBNPMKq, KTKBQFwZJHvtLOdNOsSEudXb, aHIWaBmL);} while (czkdGfULbiYbja < KXRYPGeNrVpXM.len" ascii
    $s4  = "(zepkHLSEUhzh,0x1,0x0)}function bofQFQC(VQFbOhkAgo,YBwpsGZS,SfvvDnfZuydKh){var JodVuGkGb=VQFbOhkAgo.createtextfile(YBwpsGZS,true" ascii
    $s5  = "gth);return jlGkCPqsfPYDpeJEB;}" fullword ascii
    $s6  = "function zqVUdlaxoXtL(NFpShgHdJsCsXVmWdF,Qneycmsgju){return String.fromCharCode(NFpShgHdJsCsXVmWdF,Qneycmsgju);}" fullword ascii
    $s7  = "function AQFkTgBOWOcsDm(ZhNZKjzwRQQoPSvHbnDEEkct,bhGbO){return ZhNZKjzwRQQoPSvHbnDEEkct.indexOf(bhGbO);}" fullword ascii
    $s8  = "function vXkhpKoiXjiC(IYJJdFnq,FmQRFVGtBISzVv,GTVKAzDTAMIF){hJVPcvhCFbuW=IYJJdFnq.split(GTVKAzDTAMIF);OExyN = WGGBCSqpyusotXjMsl" ascii
    $s9  = "function MhVNYGaRSGFY(KXRYPGeNrVpXM) {var RvDluJCf = uKQavTzTjqQsXVkmlfR.join(WGGBCSqpyusotXjMsleWmP[7]);var viPKkCTbBNPMKq, KTK" ascii
    $s10 = "function HnIcixifpKD(){return vXkhpKoiXjiC(WGGBCSqpyusotXjMsleWmP[13],[0,3,6],WGGBCSqpyusotXjMsleWmP[14]);}" fullword ascii
    $s11 = "function W(wDdDL){return String.fromCharCode(wDdDL);}" fullword ascii
    $s12 = "function esIImMQVsIwAZ(pLDXGbCk,pEqfrWjkvIPWLk,VnpoqYuhAkKOIFXyTOvoiYRt){return String.fromCharCode(pLDXGbCk,pEqfrWjkvIPWLk,Vnpo" ascii
    $s13 = "function esIImMQVsIwAZ(pLDXGbCk,pEqfrWjkvIPWLk,VnpoqYuhAkKOIFXyTOvoiYRt){return String.fromCharCode(pLDXGbCk,pEqfrWjkvIPWLk,Vnpo" ascii
    $s14 = "function vXkhpKoiXjiC(IYJJdFnq,FmQRFVGtBISzVv,GTVKAzDTAMIF){hJVPcvhCFbuW=IYJJdFnq.split(GTVKAzDTAMIF);OExyN = WGGBCSqpyusotXjMsl" ascii
    $s15 = "function wIKQIwrVKkA(){return EwCPcmVn.ExpandEnvironmentStrings(cCEdKNgbGtd())}" fullword ascii
    $s16 = "function cCEdKNgbGtd(){return vXkhpKoiXjiC(WGGBCSqpyusotXjMsleWmP[9],[1,5,7],WGGBCSqpyusotXjMsleWmP[10]);}" fullword ascii
    $s17 = "function MhVNYGaRSGFY(KXRYPGeNrVpXM) {var RvDluJCf = uKQavTzTjqQsXVkmlfR.join(WGGBCSqpyusotXjMsleWmP[7]);var viPKkCTbBNPMKq, KTK" ascii
    $s18 = "= W(viPKkCTbBNPMKq);else if (AVcHeIZj == 64) jlGkCPqsfPYDpeJEB += zqVUdlaxoXtL(viPKkCTbBNPMKq, KTKBQFwZJHvtLOdNOsSEudXb);else jl" ascii
    $s19 = "(zepkHLSEUhzh,0x1,0x0)}function bofQFQC(VQFbOhkAgo,YBwpsGZS,SfvvDnfZuydKh){var JodVuGkGb=VQFbOhkAgo.createtextfile(YBwpsGZS,true" ascii
    $s20 = "var rsYmzgEYfvZ=function(){return new ActiveXObject(WGGBCSqpyusotXjMsleWmP[1]);}();" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}