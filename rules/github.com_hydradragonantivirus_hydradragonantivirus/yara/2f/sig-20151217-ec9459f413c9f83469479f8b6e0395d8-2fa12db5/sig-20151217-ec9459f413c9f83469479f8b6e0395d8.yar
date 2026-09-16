rule sig_20151217_ec9459f413c9f83469479f8b6e0395d8 {
  meta:
    description = "datamaliciousorder - file 20151217_ec9459f413c9f83469479f8b6e0395d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa7c14b8ab46144950d041d14d5eb179f0fdb512f3e70133f7c121fc85390268"

  strings:
    $s1  = "function uybaAwPOZgQAvyHVW(IUjbf){KRHGEhweXEf= '';WBgMOJknrUB=Math.round((Math.pow(Math.sin(847), 2) + Math.pow(Math.cos(847), 2" ascii
    $s2  = "(Math.cos(33), 2) - 1)));} PHEHfcUHo[WBgMOJknrUB]++;}WBgMOJknrUB++;} return KRHGEhweXEf}" fullword ascii
    $s3  = "th.pow(Math.cos(773), 2) - 1)); while(true) { if(PHEHfcUHo[WBgMOJknrUB] > IUjbf[WBgMOJknrUB].length-(530+318)/848) { break; } if" ascii
    $s4  = ") - 1));while(true){if (WBgMOJknrUB >= (3670+338)/668){break;}PHEHfcUHo[WBgMOJknrUB]=Math.round((Math.pow(Math.sin(773), 2) + Ma" ascii
    $s5  = "function uybaAwPOZgQAvyHVW(IUjbf){KRHGEhweXEf= '';WBgMOJknrUB=Math.round((Math.pow(Math.sin(847), 2) + Math.pow(Math.cos(847), 2" ascii
    $s6  = "function ncdnlPC(nrUibeUWBLwxKDHXzqarbWYRyuLGlLtZJTtS) {return !StrlNmlItCB(zYzjjAudocMnzyY(nrUibeUWBLwxKDHXzqarbWYRyuLGlLtZJTtS" ascii
    $s7  = "var R = new Array();R[0]=[];R[0][0]='d';R[0][1]='a';R[0][2]='d';R[0][3]='a';R[0][4]='46';R[0][5]='3d';R[0][6]='42';R[0][7]='14';" ascii
    $s8  = "Z);return YcGbk;}" fullword ascii
    $s9  = "var R = new Array();R[0]=[];R[0][0]='d';R[0][1]='a';R[0][2]='d';R[0][3]='a';R[0][4]='46';R[0][5]='3d';R[0][6]='42';R[0][7]='14';" ascii
    $s10 = "function USdKGxCIUrFDgbr(SUdOzOygiBZhywTeq,mduStHczCChxKtARsGknCOKlHiVVQyEGCc,pIRfiCgVIkijIjyBEgxQfsZwHNwWjMENCCr){eval(SUdOzOyg" ascii
    $s11 = "function y(cHNZoXUuGqEE,BqDMbQkkRnYIXl){cHNZoXUuGqEE.push(BqDMbQkkRnYIXl);}" fullword ascii
    $s12 = "function ncdnlPC(nrUibeUWBLwxKDHXzqarbWYRyuLGlLtZJTtS) {return !StrlNmlItCB(zYzjjAudocMnzyY(nrUibeUWBLwxKDHXzqarbWYRyuLGlLtZJTtS" ascii
    $s13 = "function WQxwnhzlWlkS(XiRAMVaTtxjBM) {return isFinite(XiRAMVaTtxjBM);}" fullword ascii
    $s14 = "function USdKGxCIUrFDgbr(SUdOzOygiBZhywTeq,mduStHczCChxKtARsGknCOKlHiVVQyEGCc,pIRfiCgVIkijIjyBEgxQfsZwHNwWjMENCCr){eval(SUdOzOyg" ascii
    $s15 = "function wCFWOruVZIGuNimFmLnpNEJAXaFqdSWhYFZKGqHOIrUyfbCcTMGYbc(bnMUcqWgHEsEg,AjVYpbkOPjGbBQ){ return bZoqtJh[lfvfpbsh[xKETI(bnM" ascii
    $s16 = "function wCFWOruVZIGuNimFmLnpNEJAXaFqdSWhYFZKGqHOIrUyfbCcTMGYbc(bnMUcqWgHEsEg,AjVYpbkOPjGbBQ){ return bZoqtJh[lfvfpbsh[xKETI(bnM" ascii
    $s17 = "function l(tqpGKwaFusTqpy,JZbKtkjUVdJOt,pNONlxpUWSz) {tqpGKwaFusTqpy[JZbKtkjUVdJOt]=pNONlxpUWSz;}" fullword ascii
    $s18 = "function StrlNmlItCB(jHhNvYLvyOVYle) {return isNaN(jHhNvYLvyOVYle);}" fullword ascii
    $s19 = "function UxYrxyoAkhwCahNri(JVVBcEcAEp,idwTuFWFyw) {return parseInt(JVVBcEcAEp,idwTuFWFyw);}" fullword ascii
    $s20 = "function xKETI(iJzVhmYNDyj,OhPAIRMoeQnmt,ZipUDzOZ){ekEs=UxYrxyoAkhwCahNri(iJzVhmYNDyj,OhPAIRMoeQnmt);YcGbk=ekEs.toString(ZipUDzO" ascii

  condition:
    uint16(0) == 0x666c and
    8 of them
}