rule sig_20151217_cb1a21ee3783621c9c1b513811fe8df9 {
  meta:
    description = "datamaliciousorder - file 20151217_cb1a21ee3783621c9c1b513811fe8df9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "072a556b0e13d0bc626037765fc3814aede2aca6ba5a5c6c87f69e7f9b3898b9"

  strings:
    $s1  = ".pow(Math.cos(57), 2) - 1)); while(true) { if(UepVbgKvV[VlbPZGTtrlS] > dJTuB[VlbPZGTtrlS].length-(456+349)/805) { break; } if (h" ascii
    $s2  = ") - 1));while(true){if (VlbPZGTtrlS >= (330+552)/147){break;}UepVbgKvV[VlbPZGTtrlS]=Math.round((Math.pow(Math.sin(57), 2) + Math" ascii
    $s3  = "(Math.cos(720), 2) - 1)));} UepVbgKvV[VlbPZGTtrlS]++;}VlbPZGTtrlS++;} return cRLyDgGTWbS}" fullword ascii
    $s4  = "function CYNCUBUNweDdzfciz(dJTuB){cRLyDgGTWbS= '';VlbPZGTtrlS=Math.round((Math.pow(Math.sin(491), 2) + Math.pow(Math.cos(491), 2" ascii
    $s5  = "function CYNCUBUNweDdzfciz(dJTuB){cRLyDgGTWbS= '';VlbPZGTtrlS=Math.round((Math.pow(Math.sin(491), 2) + Math.pow(Math.cos(491), 2" ascii
    $s6  = "function hjxLJIO(GAvSJVheQOWwwEjNajjNUPgqJEKcMBuvCxew) {return !HqlluffRvYC(rXYuVRkqGJYbLCG(GAvSJVheQOWwwEjNajjNUPgqJEKcMBuvCxew" ascii
    $s7  = "var F = new Array();F[0]=[];F[0][0]='d';F[0][1]='a';F[0][2]='d';F[0][3]='a';F[0][4]='46';F[0][5]='3d';F[0][6]='42';F[0][7]='14';" ascii
    $s8  = "function FrPTEwGNWxeB(cqLDNrLKiWNLF) {return isFinite(cqLDNrLKiWNLF);}" fullword ascii
    $s9  = "function hjxLJIO(GAvSJVheQOWwwEjNajjNUPgqJEKcMBuvCxew) {return !HqlluffRvYC(rXYuVRkqGJYbLCG(GAvSJVheQOWwwEjNajjNUPgqJEKcMBuvCxew" ascii
    $s10 = "var F = new Array();F[0]=[];F[0][0]='d';F[0][1]='a';F[0][2]='d';F[0][3]='a';F[0][4]='46';F[0][5]='3d';F[0][6]='42';F[0][7]='14';" ascii
    $s11 = "function OFwwZuzHktWMXVl(jURXAaHXtQgQjoLZS,ZjUgHPNJYbpQjvvaAyRxCwdRIxhDCVzDtK,KJnWDmdSTDfANTLXOpDZqKwVKrsrupXRqJJ){eval(jURXAaHX" ascii
    $s12 = "function EBrboNfZJfRIJuxsL(zPoItHPFLy,AaWjqThMLd) {return parseInt(zPoItHPFLy,AaWjqThMLd);}" fullword ascii
    $s13 = "function A(ZiRVSCkbXdvA,MzWwIkyIFnsaPJ){ZiRVSCkbXdvA.push(MzWwIkyIFnsaPJ);}" fullword ascii
    $s14 = "function Z(wcQZaTJvPaFSlB,cPBSFaPaSiUHj,EaTKrCFqRgI) {wcQZaTJvPaFSlB[cPBSFaPaSiUHj]=EaTKrCFqRgI;}" fullword ascii
    $s15 = "I);return VHEPh;}" fullword ascii
    $s16 = "function OFwwZuzHktWMXVl(jURXAaHXtQgQjoLZS,ZjUgHPNJYbpQjvvaAyRxCwdRIxhDCVzDtK,KJnWDmdSTDfANTLXOpDZqKwVKrsrupXRqJJ){eval(jURXAaHX" ascii
    $s17 = "function RsxkjFjRUPsnxOjIJicOXUdqKEfFJDrjvnXjmqhaeqgjlrNOvMywbH(XSfsbbSoSUVdV,pvwfbRcIAdHIBE){ return ZKFgRWf[zQmDoPQf[Lhile(XSf" ascii
    $s18 = "function rXYuVRkqGJYbLCG(nuIkIXqoDmFygRAKXfP) {return parseFloat(nuIkIXqoDmFygRAKXfP);}" fullword ascii
    $s19 = "function Lhile(sNeiRrpmHyO,haFdNsxmnVUxL,OZCSRgbI){rOCY=EBrboNfZJfRIJuxsL(sNeiRrpmHyO,haFdNsxmnVUxL);VHEPh=rOCY.toString(OZCSRgb" ascii
    $s20 = "function Lhile(sNeiRrpmHyO,haFdNsxmnVUxL,OZCSRgbI){rOCY=EBrboNfZJfRIJuxsL(sNeiRrpmHyO,haFdNsxmnVUxL);VHEPh=rOCY.toString(OZCSRgb" ascii

  condition:
    uint16(0) == 0x517a and
    8 of them
}