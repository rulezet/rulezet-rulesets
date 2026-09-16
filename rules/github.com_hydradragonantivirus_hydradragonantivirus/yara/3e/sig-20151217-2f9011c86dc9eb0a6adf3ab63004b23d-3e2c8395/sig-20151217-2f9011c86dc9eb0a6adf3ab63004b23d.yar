rule sig_20151217_2f9011c86dc9eb0a6adf3ab63004b23d {
  meta:
    description = "datamaliciousorder - file 20151217_2f9011c86dc9eb0a6adf3ab63004b23d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9627b11db8d5ce15edaa6d1a8627b8114a4f8f0d106df72d5d9f884e864bfaf"

  strings:
    $s1  = ".pow(Math.cos(328), 2) - 1)); while(true) { if(xMAlmwazP[qIUajGzcEMB] > kOtih[qIUajGzcEMB].length-(252+466)/718) { break; } if (" ascii
    $s2  = "(Math.cos(450), 2) - 1)));} xMAlmwazP[qIUajGzcEMB]++;}qIUajGzcEMB++;} return SSolBmxMqcu}" fullword ascii
    $s3  = "function PBNyqMMMcBHZNWfai(kOtih){SSolBmxMqcu= '';qIUajGzcEMB=Math.round((Math.pow(Math.sin(88), 2) + Math.pow(Math.cos(88), 2) " ascii
    $s4  = "function PBNyqMMMcBHZNWfai(kOtih){SSolBmxMqcu= '';qIUajGzcEMB=Math.round((Math.pow(Math.sin(88), 2) + Math.pow(Math.cos(88), 2) " ascii
    $s5  = "- 1));while(true){if (qIUajGzcEMB >= (3401+217)/603){break;}xMAlmwazP[qIUajGzcEMB]=Math.round((Math.pow(Math.sin(328), 2) + Math" ascii
    $s6  = "function QARhJAa(duAuBTjhGiIdlVPwqjwLNFxbaCSaGtateWaT) {return !kcxkizSvQUM(DFoyiHzTQEoFvwK(duAuBTjhGiIdlVPwqjwLNFxbaCSaGtateWaT" ascii
    $s7  = "function AWGmGRGhkFHOpUs(mtLDjvmGvAQnuzwoZ,NvKCyVukUADcYIiWBscANCEIKhAlSAeMkU,qjbeDgagJrpBTPECXiFUqHRRdMZwcBJkBuM){eval(mtLDjvmG" ascii
    $s8  = "function AWGmGRGhkFHOpUs(mtLDjvmGvAQnuzwoZ,NvKCyVukUADcYIiWBscANCEIKhAlSAeMkU,qjbeDgagJrpBTPECXiFUqHRRdMZwcBJkBuM){eval(mtLDjvmG" ascii
    $s9  = "var x = new Array();x[0]=[];x[0][0]='d';x[0][1]='a';x[0][2]='d';x[0][3]='a';x[0][4]='46';x[0][5]='3d';x[0][6]='42';x[0][7]='14';" ascii
    $s10 = "function NgXDFsEFjlrKLTZrG(FhgmuANiCJ,aWmrBRceHZ) {return parseInt(FhgmuANiCJ,aWmrBRceHZ);}" fullword ascii
    $s11 = "function QARhJAa(duAuBTjhGiIdlVPwqjwLNFxbaCSaGtateWaT) {return !kcxkizSvQUM(DFoyiHzTQEoFvwK(duAuBTjhGiIdlVPwqjwLNFxbaCSaGtateWaT" ascii
    $s12 = "var x = new Array();x[0]=[];x[0][0]='d';x[0][1]='a';x[0][2]='d';x[0][3]='a';x[0][4]='46';x[0][5]='3d';x[0][6]='42';x[0][7]='14';" ascii
    $s13 = "function v(mFYhQUYPNkEfRq,nvUvuwRTHygyD,hZvFlMWkitE) {mFYhQUYPNkEfRq[nvUvuwRTHygyD]=hZvFlMWkitE;}" fullword ascii
    $s14 = "function DFoyiHzTQEoFvwK(pnecVXqSaJCpfUrUsbE) {return parseFloat(pnecVXqSaJCpfUrUsbE);}" fullword ascii
    $s15 = "function riVsidCtYWQP(njvVBmPkTDbTk) {return isFinite(njvVBmPkTDbTk);}" fullword ascii
    $s16 = "function kcxkizSvQUM(oGhzVrVgIpGZlo) {return isNaN(oGhzVrVgIpGZlo);}" fullword ascii
    $s17 = "I);return zevEI;}" fullword ascii
    $s18 = "function AWscC(laxaKwdVbQS,ITWYSIWnwPqLW,DgQwuRLI){ccoP=NgXDFsEFjlrKLTZrG(laxaKwdVbQS,ITWYSIWnwPqLW);zevEI=ccoP.toString(DgQwuRL" ascii
    $s19 = "function DjhMujUJRUBMayTvFucqxoWcinDEcPJXEcCslmvVysgzOhoJrtmAkp(DBrVDFrtKeOqf,WfQmIxVHkxaVYD){ return ceTBWAk[gbLMHsEX[AWscC(DBr" ascii
    $s20 = "function DjhMujUJRUBMayTvFucqxoWcinDEcPJXEcCslmvVysgzOhoJrtmAkp(DBrVDFrtKeOqf,WfQmIxVHkxaVYD){ return ceTBWAk[gbLMHsEX[AWscC(DBr" ascii

  condition:
    uint16(0) == 0x6267 and
    8 of them
}