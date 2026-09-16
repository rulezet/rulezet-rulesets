rule sig_20160531_cf7ca4f8c20b918aca2e14d4a6e31095 {
  meta:
    description = "datamaliciousorder - file 20160531_cf7ca4f8c20b918aca2e14d4a6e31095.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f474a08cdce44971f27dc40d0f2cdaf31fe2605fddd398f564e33d02a2207e09"

  strings:
    $s1  = "var DytnFWwOy=function(){return WScript.CreateObject(QyPDrlMFIB[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function jjISHOAagKPR(LjvSTjrFWoXQzWzn,YmtucbUuV){return LjvSTjrFWoXQzWzn.charAt(YmtucbUuV);}" fullword ascii
    $s3  = "function oYADJTRyS(){return dKedBBljM(QyPDrlMFIB[11],[2,4,8,10],QyPDrlMFIB[12]);}" fullword ascii
    $s4  = "function pHHUIaWYqmic(pjgVPbIDeyrMy) {var qMJJd = mXRjAWkpatBlsxAN.join(QyPDrlMFIB[7]);var mvGRcFYpbCLSfolTwcDTaL, OUBJFWLLpytXB" ascii
    $s5  = "function pHHUIaWYqmic(pjgVPbIDeyrMy) {var qMJJd = mXRjAWkpatBlsxAN.join(QyPDrlMFIB[7]);var mvGRcFYpbCLSfolTwcDTaL, OUBJFWLLpytXB" ascii
    $s6  = "Weg]];}return dAVdzOvuoUZWa.substring(3,dAVdzOvuoUZWa.length);}" fullword ascii
    $s7  = "function DnwzGkDPwAi(){return DytnFWwOy.ExpandEnvironmentStrings(xgmlkfP())}" fullword ascii
    $s8  = "function FujwLNdaTixcX(){return dKedBBljM(QyPDrlMFIB[13],[0,3,6],QyPDrlMFIB[14]);}" fullword ascii
    $s9  = "function ZhCtcfdjMeMI(fYKaxMo,MxIkcWuGLH) {var cLJVF=[QyPDrlMFIB[15]];fYKaxMo[cLJVF[0]]" fullword ascii
    $s10 = " 64) TIivyqQPbTyhD += Vr(mvGRcFYpbCLSfolTwcDTaL);else if (wcWEnwBoNLlkNyX == 64) TIivyqQPbTyhD += wCpHGxLIhfMPkXIPGa(mvGRcFYpbCL" ascii
    $s11 = "function xgmlkfP(){return dKedBBljM(QyPDrlMFIB[9],[1,5,7],QyPDrlMFIB[10]);}" fullword ascii
    $s12 = "function dKedBBljM(mSXgbYIXHzGNo,hMWOwJRTnwZljM,cfDFPDn){WziZzkoTLW=mSXgbYIXHzGNo.split(cfDFPDn);dAVdzOvuoUZWa = QyPDrlMFIB[0];f" ascii
    $s13 = "function dKedBBljM(mSXgbYIXHzGNo,hMWOwJRTnwZljM,cfDFPDn){WziZzkoTLW=mSXgbYIXHzGNo.split(cfDFPDn);dAVdzOvuoUZWa = QyPDrlMFIB[0];f" ascii
    $s14 = "function Vr(YdiFwRvJLSFse){return String.fromCharCode(YdiFwRvJLSFse);}" fullword ascii
    $s15 = "function OMXKwg(TBwQTwVCPUhSBCbJold,JPUiuOdrVIZsoNMDyevT,MiCMVNsoKHvQLgbv){return String.fromCharCode(TBwQTwVCPUhSBCbJold,JPUiuO" ascii
    $s16 = "function wCpHGxLIhfMPkXIPGa(TOFKUSkTnZIUkaFp,HvDMzNcqHlenaov){return String.fromCharCode(TOFKUSkTnZIUkaFp,HvDMzNcqHlenaov);}" fullword ascii
    $s17 = "Qmtpc < pjgVPbIDeyrMy.length);return TIivyqQPbTyhD;}" fullword ascii
    $s18 = "SfolTwcDTaL, OUBJFWLLpytXBo);else TIivyqQPbTyhD += OMXKwg(mvGRcFYpbCLSfolTwcDTaL, OUBJFWLLpytXBo, MUyLsxJcFYfutPRjM);} while (ZP" ascii
    $s19 = "(MxIkcWuGLH,0x1,0x0)}function JHqlnYs(zBceWPtuvJtlno,xIBLL,dYxDpDAnYPuu){var yBcilR=zBceWPtuvJtlno.createtextfile(xIBLL,true);yB" ascii
    $s20 = "function OMXKwg(TBwQTwVCPUhSBCbJold,JPUiuOdrVIZsoNMDyevT,MiCMVNsoKHvQLgbv){return String.fromCharCode(TBwQTwVCPUhSBCbJold,JPUiuO" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}