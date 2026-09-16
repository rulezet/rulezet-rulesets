rule sig_20160527_0988dd3e56ee89fe5631120c45dd8052 {
  meta:
    description = "datamaliciousorder - file 20160527_0988dd3e56ee89fe5631120c45dd8052.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2bbfe8fbeecfd838ff27a97338fbd1ef00f4b79d75e683a213162f368783f5e"

  strings:
    $s1  = "function uCEoRYor() {return WScript;}function zdNbekivUt(){return MUOefnMoIlw.ExpandEnvironmentStrings(DTIOQXgedw())}" fullword ascii
    $s2  = "function AHQaFqyGSuyDDDfiMNd(tTGncoXpEkfeLAxnIKmeS,bpAgBnXciYgPApftN){return tTGncoXpEkfeLAxnIKmeS.charAt(bpAgBnXciYgPApftN);}" fullword ascii
    $s3  = "push(\"U\");RNiSHvBeQfpR.push(\"V\");RNiSHvBeQfpR.push(\"W\");RNiSHvBeQfpR.push(\"X\");RNiSHvBeQfpR.push(\"Y\");RNiSHvBeQfpR.pus" ascii
    $s4  = "function BaaVbiSnvZTkDj(uLXoBbFeHK,HrQrEJxoeCjGxrgyEaM){return String.fromCharCode(uLXoBbFeHK,HrQrEJxoeCjGxrgyEaM);}" fullword ascii
    $s5  = " += BaaVbiSnvZTkDj(QYXOvkeVTHXC, JkjBuRGVQmgUBCzPnhLeKPfI);else jZQgEcSmAAYHJkVncSX += ljShbUsXcwWRHXWqxA(QYXOvkeVTHXC, JkjBuRGV" ascii
    $s6  = "=0;RHRab<rLDekh.length;RHRab++) {GCEEcTxJeIkOzA+=HKLFAmONrFn[rLDekh[RHRab]];}return GCEEcTxJeIkOzA.substring(3,GCEEcTxJeIkOzA.le" ascii
    $s7  = "VaiBN & 0xff;if (ZiRPrivthruRGdtSkLXyg == 64) jZQgEcSmAAYHJkVncSX += y(QYXOvkeVTHXC);else if (YRDzzFC == 64) jZQgEcSmAAYHJkVncSX" ascii
    $s8  = "QmgUBCzPnhLeKPfI, uMmlIAKyLkXVEvgbT);} while (mClAjKODPVMpLBGR < XuGMRqbCsjBNS.length);return jZQgEcSmAAYHJkVncSX;}" fullword ascii
    $s9  = "function y(oAvVvMMseBfHjRk){return String.fromCharCode(oAvVvMMseBfHjRk);}" fullword ascii
    $s10 = "function ljShbUsXcwWRHXWqxA(VkxVRGV,pWzyFOlWIWLfRSQjyEK,JeezPp){return String.fromCharCode(VkxVRGV,pWzyFOlWIWLfRSQjyEK,JeezPp);}" ascii
    $s11 = "function fQyaMyYCQptAe(mVodYrCOmBJ,TjxaJvyBq) {var WKyKP=[OhQnUObPUNzCaIJSChVj[15]];mVodYrCOmBJ[WKyKP[0]](TjxaJvyBq,0x1,0x0)}" fullword ascii
    $s12 = "var VCSDZNwwFKqBOp = RRwdWQJlIKLp.createtextfile(MUOefnMoIlw.ExpandEnvironmentStrings(OhQnUObPUNzCaIJSChVj[2]+OhQnUObPUNzCaIJSCh" ascii
    $s13 = "function NfQzlFAeWKJP(kMRdgklTGt,CAmtZFgBGVRdKoDnOMxQvvg){return kMRdgklTGt.indexOf(CAmtZFgBGVRdKoDnOMxQvvg);}" fullword ascii
    $s14 = "var RRwdWQJlIKLp=function(){return new ActiveXObject(OhQnUObPUNzCaIJSChVj[0]);}();" fullword ascii
    $s15 = "function DTIOQXgedw(){return IwBULZ(OhQnUObPUNzCaIJSChVj[8],[1,5,7],OhQnUObPUNzCaIJSChVj[9]);}" fullword ascii
    $s16 = "function WMIyWaTwvFoZ(){return IwBULZ(OhQnUObPUNzCaIJSChVj[12],[0,3,6],OhQnUObPUNzCaIJSChVj[13]);}" fullword ascii
    $s17 = "Vj[3])+String.fromCharCode(92)+OhQnUObPUNzCaIJSChVj[4],true);" fullword ascii
    $s18 = "function DaNKO(XuGMRqbCsjBNS) {var SmgNTBpIV = RNiSHvBeQfpR.join(OhQnUObPUNzCaIJSChVj[6]);var QYXOvkeVTHXC, JkjBuRGVQmgUBCzPnhLe" ascii
    $s19 = "function DaNKO(XuGMRqbCsjBNS) {var SmgNTBpIV = RNiSHvBeQfpR.join(OhQnUObPUNzCaIJSChVj[6]);var QYXOvkeVTHXC, JkjBuRGVQmgUBCzPnhLe" ascii
    $s20 = "function IwBULZ(ObOPwxZpKG,rLDekh,rjgGS){HKLFAmONrFn=ObOPwxZpKG.split(rjgGS);GCEEcTxJeIkOzA = OhQnUObPUNzCaIJSChVj[14];for(RHRab" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}