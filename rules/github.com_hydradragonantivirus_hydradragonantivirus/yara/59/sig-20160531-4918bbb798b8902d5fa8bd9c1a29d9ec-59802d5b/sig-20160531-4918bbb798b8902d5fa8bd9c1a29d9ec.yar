rule sig_20160531_4918bbb798b8902d5fa8bd9c1a29d9ec {
  meta:
    description = "datamaliciousorder - file 20160531_4918bbb798b8902d5fa8bd9c1a29d9ec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "471da07a0a9919e79a7098895b0eea128706ef469f0805330b6a46c0525b3a14"

  strings:
    $s1  = "var HiIiCxnkDTKin=function(){return WScript.CreateObject(ThiRfg[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function UHzAnnajopOSTnDwS(WAGGmVeJfzXIowVz,CXGqdJpj,CZvpDvcwLNaxBjUHGEZbT){return String.fromCharCode(WAGGmVeJfzXIowVz,CXGqdJpj" ascii
    $s3  = "function JUOAOaI(TLrPWXfEtSPsm) {var VQRHsRsmExeybeyNm = HNVibRgpXKXfUR.join(ThiRfg[7]);var VGyBjPOKm, mPKJIFGtJNWQqqLQH, WCURRF" ascii
    $s4  = "function ypPiYmibBEH(BrZUmVcRBGFeGsJrZL,dHGqynWjLqQjtQ){return BrZUmVcRBGFeGsJrZL.charAt(dHGqynWjLqQjtQ);}" fullword ascii
    $s5  = "function UHzAnnajopOSTnDwS(WAGGmVeJfzXIowVz,CXGqdJpj,CZvpDvcwLNaxBjUHGEZbT){return String.fromCharCode(WAGGmVeJfzXIowVz,CXGqdJpj" ascii
    $s6  = "mPKJIFGtJNWQqqLQH);else MWdiPQfVYmM += UHzAnnajopOSTnDwS(VGyBjPOKm, mPKJIFGtJNWQqqLQH, WCURRFMEnRSRfX);} while (vxmYCDWltr < TLr" ascii
    $s7  = "(ItFHiPowGlHHm,0x1,0x0)}function kOFLHVwl(GgSosxI,pwuaB,BrUNXUWTuEsM){var awaXFKubo=GgSosxI.createtextfile(pwuaB,true);awaXFKubo" ascii
    $s8  = "PWXfEtSPsm.length);return MWdiPQfVYmM;}" fullword ascii
    $s9  = "(ItFHiPowGlHHm,0x1,0x0)}function kOFLHVwl(GgSosxI,pwuaB,BrUNXUWTuEsM){var awaXFKubo=GgSosxI.createtextfile(pwuaB,true);awaXFKubo" ascii
    $s10 = "push(\"t\");HNVibRgpXKXfUR.push(\"u\");HNVibRgpXKXfUR.push(\"v\");HNVibRgpXKXfUR.push(\"w\");HNVibRgpXKXfUR.push(\"x\");HNVibRgp" ascii
    $s11 = "function MjIesRges(HKUdwCEoW,lSUjIEwmUBX){return String.fromCharCode(HKUdwCEoW,lSUjIEwmUBX);}" fullword ascii
    $s12 = "0;UpHZJQTFxd<EqZxo.length;UpHZJQTFxd++) {GhbliuaLNAcdIi+=ojKFyFvpp[EqZxo[UpHZJQTFxd]];}return GhbliuaLNAcdIi.substring(3,Ghbliua" ascii
    $s13 = "function JUOAOaI(TLrPWXfEtSPsm) {var VQRHsRsmExeybeyNm = HNVibRgpXKXfUR.join(ThiRfg[7]);var VGyBjPOKm, mPKJIFGtJNWQqqLQH, WCURRF" ascii
    $s14 = "function rIMHikcMIx(BISsbLjCDIc,EqZxo,VOBMmSSq){ojKFyFvpp=BISsbLjCDIc.split(VOBMmSSq);GhbliuaLNAcdIi = ThiRfg[0];for(UpHZJQTFxd=" ascii
    $s15 = "var BQvtyfAQv=function(){return new ActiveXObject(ThiRfg[1]);}();" fullword ascii
    $s16 = "function rIMHikcMIx(BISsbLjCDIc,EqZxo,VOBMmSSq){ojKFyFvpp=BISsbLjCDIc.split(VOBMmSSq);GhbliuaLNAcdIi = ThiRfg[0];for(UpHZJQTFxd=" ascii
    $s17 = "function PHncOeE(){return rIMHikcMIx(ThiRfg[9],[1,5,7],ThiRfg[10]);}" fullword ascii
    $s18 = "f (STqfAOSQNRrJkLoSmYlU == 64) MWdiPQfVYmM += G(VGyBjPOKm);else if (ivAXYoRkgKpXLYNl == 64) MWdiPQfVYmM += MjIesRges(VGyBjPOKm, " ascii
    $s19 = "function lZnrrqpIHSX(){return rIMHikcMIx(ThiRfg[11],[2,4,8,10],ThiRfg[12]);}" fullword ascii
    $s20 = "function ZvrqajUSYMSHhjh(THBRYXqgjfnHfRcxkixV,dLkwv){return THBRYXqgjfnHfRcxkixV.indexOf(dLkwv);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}