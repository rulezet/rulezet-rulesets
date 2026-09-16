rule sig_20160523_23f79faf032b3f9ea9d7cfb13c72a145 {
  meta:
    description = "datamaliciousorder - file 20160523_23f79faf032b3f9ea9d7cfb13c72a145.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "929112c22c912308c2ef19f4fdda6b91f328d0b2f495669755562ad5c3f193b4"

  strings:
    $s1  = "function mXVhrnZz(aDsSL) {var IBBsbiNm=qnyNvanJAislCySHd[13];for(var RNyID=0;RNyID<aDsSL;RNyID++){wqrNl+=IBBsbiNm.charAt(Math.fl" ascii
    $s2  = "function mXVhrnZz(aDsSL) {var IBBsbiNm=qnyNvanJAislCySHd[13];for(var RNyID=0;RNyID<aDsSL;RNyID++){wqrNl+=IBBsbiNm.charAt(Math.fl" ascii
    $s3  = "function txIvlmikeS() {return/*BjeFcdImZeHelFIFMhjdIWSHbzcXIneMKQIimJBDhpGBTnPCwfgsbbtEFIomevgKevLsqwQgjnnwTsXjIJMsglEEJuTvSJqDC" ascii
    $s4  = "function ZKRMzrzIyv(VKupRZRc,PqjyknFtOCFc) {VKupRZRc.Run(PqjyknFtOCFc, 0x1, 0x0);}" fullword ascii
    $s5  = "oor(Math.random()*IBBsbiNm.length));}return wqrNl;}" fullword ascii
    $s6  = "function MqlQP(dUmKXxAE,oGPNKt,vToGElApB){NkuPF=dUmKXxAE.split(vToGElApB);teRMzJZ = qnyNvanJAislCySHd[12];for(YeCcrRxl=0;YeCcrRx" ascii
    $s7  = "function ppuVm(sVqhwbLt,CYhcr,ngbkgoYyzI){FKeU(sVqhwbLt);oPpMJBSN(sVqhwbLt);ssZOuLe(sVqhwbLt,CYhcr);HByQWztSq(sVqhwbLt);XZPX(sVq" ascii
    $s8  = "function ttReXIa() {var MWKv=100000;var EsXyzU = 100;return cgMMvUS()*(MWKv-EsXyzU)+EsXyzU;}" fullword ascii
    $s9  = "function oPpMJBSN(iLZoiPRTT) {iLZoiPRTT.type=1;}" fullword ascii
    $s10 = "function xeFXk(DYUcqe){return new ActiveXObject(DYUcqe);}" fullword ascii
    $s11 = "function ssZOuLe(NDJu,AzLSy) {NDJu.write(AzLSy);}" fullword ascii
    $s12 = "HPNV, false);rfaSnYo.send();}" fullword ascii
    $s13 = "function HmaK(WPHPNV,rfaSnYo){VArU = qnyNvanJAislCySHd[10].split(qnyNvanJAislCySHd[11]);rfaSnYo.open(VArU[0]+VArU[2]+VArU[3], WP" ascii
    $s14 = "function HByQWztSq(TYkGrY) {var jluIVnFYrm=[];TYkGrY.position=jluIVnFYrm.length*(9430341-992);}" fullword ascii
    $s15 = "function HmaK(WPHPNV,rfaSnYo){VArU = qnyNvanJAislCySHd[10].split(qnyNvanJAislCySHd[11]);rfaSnYo.open(VArU[0]+VArU[2]+VArU[3], WP" ascii
    $s16 = "function maBQUeT(OHJQd) {OHJQd.close();}" fullword ascii
    $s17 = "function kcEpbdaiSiVLB() {txIvlmikeS().Sleep(2442654-116);}" fullword ascii
    $s18 = "if(UFKr>XvsUM.length) break;" fullword ascii
    $s19 = "l<oGPNKt.length;YeCcrRxl++) {teRMzJZ+=NkuPF[oGPNKt[YeCcrRxl]];}return teRMzJZ.substring(3,teRMzJZ.length);}" fullword ascii
    $s20 = "function kNGsCk(DYUcqe){return DYUcqe.ExpandEnvironmentStrings(qnyNvanJAislCySHd[9])}" fullword ascii

  condition:
    uint16(0) == 0x0727 and
    8 of them
}