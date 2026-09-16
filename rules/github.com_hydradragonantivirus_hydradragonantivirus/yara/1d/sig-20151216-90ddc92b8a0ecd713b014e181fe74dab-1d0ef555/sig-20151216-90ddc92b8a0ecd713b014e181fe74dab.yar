rule sig_20151216_90ddc92b8a0ecd713b014e181fe74dab {
  meta:
    description = "datamaliciousorder - file 20151216_90ddc92b8a0ecd713b014e181fe74dab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c60d6b58f6544c8de0e68774510aa9e48db197c74f5e6a0eca8b8e80be15b878"

  strings:
    $s1  = "ow(Math.cos(510), 2) - 1)));} ASeJMcBrp[DBIhPXiBCkF]++;}DBIhPXiBCkF++;} return yQlynUPYIRI}" fullword ascii
    $s2  = "function HUHOPKhJwyPiOcGOX(YDbPo){yQlynUPYIRI= '';DBIhPXiBCkF=Math.round((Math.pow(Math.sin(246), 2) + Math.pow(Math.cos(246), 2" ascii
    $s3  = "th.pow(Math.cos(971), 2) - 1)); while(true) { if(ASeJMcBrp[DBIhPXiBCkF] > YDbPo[DBIhPXiBCkF].length-(-278+667)/389) { break; } i" ascii
    $s4  = ") - 1));while(true){if (DBIhPXiBCkF >= (3820+218)/673){break;}ASeJMcBrp[DBIhPXiBCkF]=Math.round((Math.pow(Math.sin(971), 2) + Ma" ascii
    $s5  = "function HUHOPKhJwyPiOcGOX(YDbPo){yQlynUPYIRI= '';DBIhPXiBCkF=Math.round((Math.pow(Math.sin(246), 2) + Math.pow(Math.cos(246), 2" ascii
    $s6  = "function tNJMxQs(KcdvkSrEGlntSHfOpPPlEpwmARZPbXTxsrBW) {return !JBjLolLjwtZ(qDnCKyaHDjmLRgQ(KcdvkSrEGlntSHfOpPPlEpwmARZPbXTxsrBW" ascii
    $s7  = "var K = new Array();K[0]=[];K[0][0]='d';K[0][1]='a';K[0][2]='d';K[0][3]='a';K[0][4]='46';K[0][5]='3d';K[0][6]='42';K[0][7]='14';" ascii
    $s8  = "function BmyAdBMzBMyHWXXnK(pNgAkDbOIa,UJDDweorBb) {return parseInt(pNgAkDbOIa,UJDDweorBb);}" fullword ascii
    $s9  = "function ytXnG(MfKzwyPWIYG,BOxflWyrIchyM,qJoKLFAo){oscf=BmyAdBMzBMyHWXXnK(MfKzwyPWIYG,BOxflWyrIchyM);pkcyp=oscf.toString(qJoKLFA" ascii
    $s10 = "function vLIjIWHMFECubpoqumBAxnGHQqjrbFGKToQjuSknLhyxSFChqVEmrz(qVTCCUfYqtZWn,LRHwRFrQlQuHZk){ return ZXHbXdc[zKfZmmZw[ytXnG(qVT" ascii
    $s11 = "function d(NIdvRhUyVasJjb,HWEZUWnFwxIZt,kMlThMtTKGT) {NIdvRhUyVasJjb[HWEZUWnFwxIZt]=kMlThMtTKGT;}" fullword ascii
    $s12 = "function ZqVCMlUIdMYc(xqcDIEQMcdWZe) {return isFinite(xqcDIEQMcdWZe);}" fullword ascii
    $s13 = "function ytXnG(MfKzwyPWIYG,BOxflWyrIchyM,qJoKLFAo){oscf=BmyAdBMzBMyHWXXnK(MfKzwyPWIYG,BOxflWyrIchyM);pkcyp=oscf.toString(qJoKLFA" ascii
    $s14 = "o);return pkcyp;}" fullword ascii
    $s15 = "function JBjLolLjwtZ(hpUnTMMOoOgNPT) {return isNaN(hpUnTMMOoOgNPT);}" fullword ascii
    $s16 = "function vLIjIWHMFECubpoqumBAxnGHQqjrbFGKToQjuSknLhyxSFChqVEmrz(qVTCCUfYqtZWn,LRHwRFrQlQuHZk){ return ZXHbXdc[zKfZmmZw[ytXnG(qVT" ascii
    $s17 = "function qDnCKyaHDjmLRgQ(UupkqRRvNUFfKGoHmCu) {return parseFloat(UupkqRRvNUFfKGoHmCu);}" fullword ascii
    $s18 = "function w(ndKkWSeddogk,cvKEBqaMaoxWpn){ndKkWSeddogk.push(cvKEBqaMaoxWpn);}" fullword ascii
    $s19 = "function tNJMxQs(KcdvkSrEGlntSHfOpPPlEpwmARZPbXTxsrBW) {return !JBjLolLjwtZ(qDnCKyaHDjmLRgQ(KcdvkSrEGlntSHfOpPPlEpwmARZPbXTxsrBW" ascii
    $s20 = "var K = new Array();K[0]=[];K[0][0]='d';K[0][1]='a';K[0][2]='d';K[0][3]='a';K[0][4]='46';K[0][5]='3d';K[0][6]='42';K[0][7]='14';" ascii

  condition:
    uint16(0) == 0x4b7a and
    8 of them
}