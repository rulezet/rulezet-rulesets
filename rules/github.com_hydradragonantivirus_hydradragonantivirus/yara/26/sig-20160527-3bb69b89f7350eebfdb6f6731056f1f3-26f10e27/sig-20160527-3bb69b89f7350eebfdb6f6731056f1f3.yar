rule sig_20160527_3bb69b89f7350eebfdb6f6731056f1f3 {
  meta:
    description = "datamaliciousorder - file 20160527_3bb69b89f7350eebfdb6f6731056f1f3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "573d04607a0d1f90c125c0ae412ce71a908c2b083bd1c9c9c15f8fee8b57d144"

  strings:
    $s1  = "function DHkoBuCqol() {return WScript;}function nNxGppdhyF(){return zOjxkPzQiyQyQg.ExpandEnvironmentStrings(JcyyDMGsvVI())}" fullword ascii
    $s2  = "function SyfpZiHtyjJBa(UnRwwBrCmnYpTbifslN,JLTsfnGyLhPxtNHRtkm){return UnRwwBrCmnYpTbifslN.charAt(JLTsfnGyLhPxtNHRtkm);}" fullword ascii
    $s3  = "AxameIFvVGxFd < aWUpAseFiZPmS.length);return MWmSZYnnwfMIJ;}" fullword ascii
    $s4  = "function aONhtZkDPe(VcKVpPXsdkNsRBXJkd,cCqSUK){return VcKVpPXsdkNsRBXJkd.indexOf(cCqSUK);}" fullword ascii
    $s5  = "function sMrTNqqbRd(aWUpAseFiZPmS) {var MEsEGopseWsBMcBs = wTLinuMjfBImhpqdGn.join(qSYQTQZXjjgb[6]);var lfnuzrW, BrtXJDlbRUIvv, " ascii
    $s6  = "function JcyyDMGsvVI(){return oMRID(qSYQTQZXjjgb[8],[1,5,7],qSYQTQZXjjgb[9]);}" fullword ascii
    $s7  = "function XEaWRCFWqu(){return oMRID(qSYQTQZXjjgb[10],[2,4,8,10],qSYQTQZXjjgb[11]);}" fullword ascii
    $s8  = "var iRlzcQ = XEydHvwGm.createtextfile(zOjxkPzQiyQyQg.ExpandEnvironmentStrings(qSYQTQZXjjgb[2]+qSYQTQZXjjgb[3])+String.fromCharCo" ascii
    $s9  = "var XEydHvwGm=function(){return new ActiveXObject(qSYQTQZXjjgb[0]);}();" fullword ascii
    $s10 = "vTqDQFQTgTMMoHH = OOiGtxwfnnOPYyJ & 0xff;if (mfhHfwZb == 64) MWmSZYnnwfMIJ += DI(lfnuzrW);else if (BXrAdhNglNy == 64) MWmSZYnnwf" ascii
    $s11 = "function DI(ErPrvJcPVP){return String.fromCharCode(ErPrvJcPVP);}" fullword ascii
    $s12 = "function EZNWxdmuYqKd(nbeAwHN,MMMkTYZNcg) {var ICPwbFGvcBOY=[qSYQTQZXjjgb[15]];nbeAwHN[ICPwbFGvcBOY[0]](MMMkTYZNcg,0x1,0x0)}" fullword ascii
    $s13 = "var zOjxkPzQiyQyQg=function(){return DHkoBuCqol().CreateObject(qSYQTQZXjjgb[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s14 = "de(92)+qSYQTQZXjjgb[4],true);" fullword ascii
    $s15 = "function bHLbYv(hBHYbmPsBNPpblxozEga,DzLSxchU){return String.fromCharCode(hBHYbmPsBNPpblxozEga,DzLSxchU);}" fullword ascii
    $s16 = "push(\"D\");wTLinuMjfBImhpqdGn.push(\"3\");wTLinuMjfBImhpqdGn.push(\"E\");wTLinuMjfBImhpqdGn.push(\"F\");wTLinuMjfBImhpqdGn.push" ascii
    $s17 = "function oMRID(gWGAyjqJMlDhWM,QhAXKQTZTC,FnlXf){dGyeBahGn=gWGAyjqJMlDhWM.split(FnlXf);hzbIl = qSYQTQZXjjgb[14];for(dSicaCIUooF=0" ascii
    $s18 = "function oMRID(gWGAyjqJMlDhWM,QhAXKQTZTC,FnlXf){dGyeBahGn=gWGAyjqJMlDhWM.split(FnlXf);hzbIl = qSYQTQZXjjgb[14];for(dSicaCIUooF=0" ascii
    $s19 = "function sMrTNqqbRd(aWUpAseFiZPmS) {var MEsEGopseWsBMcBs = wTLinuMjfBImhpqdGn.join(qSYQTQZXjjgb[6]);var lfnuzrW, BrtXJDlbRUIvv, " ascii
    $s20 = ";dSicaCIUooF<QhAXKQTZTC.length;dSicaCIUooF++) {hzbIl+=dGyeBahGn[QhAXKQTZTC[dSicaCIUooF]];}return hzbIl.substring(3,hzbIl.length)" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}