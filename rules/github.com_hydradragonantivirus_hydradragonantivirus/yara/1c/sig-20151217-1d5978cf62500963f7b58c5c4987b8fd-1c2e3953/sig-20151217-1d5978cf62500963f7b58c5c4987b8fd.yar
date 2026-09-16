rule sig_20151217_1d5978cf62500963f7b58c5c4987b8fd {
  meta:
    description = "datamaliciousorder - file 20151217_1d5978cf62500963f7b58c5c4987b8fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0916568203a7c1d973b1ada3a30370db60c8e3adab64a9b2a3c009829da32bd2"

  strings:
    $s1  = "pow(Math.cos(218), 2) - 1)));} kHcdLqCUe[UVwiMLGBMkb]++;}UVwiMLGBMkb++;} return XAKVweEKjIK}" fullword ascii
    $s2  = "th.pow(Math.cos(851), 2) - 1)); while(true) { if(kHcdLqCUe[UVwiMLGBMkb] > rNtzx[UVwiMLGBMkb].length-(-265+404)/139) { break; } i" ascii
    $s3  = "function lBVjNNOLHtrpEMJqJ(rNtzx){XAKVweEKjIK= '';UVwiMLGBMkb=Math.round((Math.pow(Math.sin(702), 2) + Math.pow(Math.cos(702), 2" ascii
    $s4  = ") - 1));while(true){if (UVwiMLGBMkb >= (3096+234)/555){break;}kHcdLqCUe[UVwiMLGBMkb]=Math.round((Math.pow(Math.sin(851), 2) + Ma" ascii
    $s5  = "BSkuUUrRsGhPhvqaewopsYzUUTEhhwkddjS([rNtzx[UVwiMLGBMkb][kHcdLqCUe[UVwiMLGBMkb]]], Math.round((Math.pow(Math.sin(218), 2) + Math." ascii
    $s6  = "function lBVjNNOLHtrpEMJqJ(rNtzx){XAKVweEKjIK= '';UVwiMLGBMkb=Math.round((Math.pow(Math.sin(702), 2) + Math.pow(Math.cos(702), 2" ascii
    $s7  = "function GbkaSNZ(RBwlenpFrjrQjFVbSphTxchQIcIJrkjpJqnY) {return !nrYCBCoQlWC(bKvYSfNufzUIUtw(RBwlenpFrjrQjFVbSphTxchQIcIJrkjpJqnY" ascii
    $s8  = "var G = new Array();G[0]=[];G[0][0]='d';G[0][1]='a';G[0][2]='d';G[0][3]='a';G[0][4]='46';G[0][5]='3d';G[0][6]='42';G[0][7]='14';" ascii
    $s9  = "function p(gqyogSIEILrkFS,xaYBjNGIEkDAn,aQKMjWFlDmr) {gqyogSIEILrkFS[xaYBjNGIEkDAn]=aQKMjWFlDmr;}" fullword ascii
    $s10 = "function JBLvS(bJknMXoiNyc,sQFaZlViUiLkc,XnaiKWOV){uVUy=jlaULVHCfYoXjNTkJ(bJknMXoiNyc,sQFaZlViUiLkc);WVZex=uVUy.toString(XnaiKWO" ascii
    $s11 = "function CVrWedJWGzQmuvuLLClBSkuUUrRsGhPhvqaewopsYzUUTEhhwkddjS(TIRALSgtbLmTY,SrcjWoBAOlEbji){ return tefgHRA[ZeFsXxZf[JBLvS(TIR" ascii
    $s12 = "function ScUESYegGBav(DENsQlgUrySpT) {return isFinite(DENsQlgUrySpT);}" fullword ascii
    $s13 = "function fTyCbPhOmkCzsYI(uCkuEhmXLvPIwXzNM,YCBXPEvBbVGDYCUuTblZvlpHYUxZivaXRz,fRFdXhStkeAFAVQaquAVYGcKNUAXbXUMiMH){eval(uCkuEhmX" ascii
    $s14 = "var G = new Array();G[0]=[];G[0][0]='d';G[0][1]='a';G[0][2]='d';G[0][3]='a';G[0][4]='46';G[0][5]='3d';G[0][6]='42';G[0][7]='14';" ascii
    $s15 = "function T(ceXqzKePWSlN,xMyoykCjTnuRfM){ceXqzKePWSlN.push(xMyoykCjTnuRfM);}" fullword ascii
    $s16 = "function JBLvS(bJknMXoiNyc,sQFaZlViUiLkc,XnaiKWOV){uVUy=jlaULVHCfYoXjNTkJ(bJknMXoiNyc,sQFaZlViUiLkc);WVZex=uVUy.toString(XnaiKWO" ascii
    $s17 = "function CVrWedJWGzQmuvuLLClBSkuUUrRsGhPhvqaewopsYzUUTEhhwkddjS(TIRALSgtbLmTY,SrcjWoBAOlEbji){ return tefgHRA[ZeFsXxZf[JBLvS(TIR" ascii
    $s18 = "V);return WVZex;}" fullword ascii
    $s19 = "function fTyCbPhOmkCzsYI(uCkuEhmXLvPIwXzNM,YCBXPEvBbVGDYCUuTblZvlpHYUxZivaXRz,fRFdXhStkeAFAVQaquAVYGcKNUAXbXUMiMH){eval(uCkuEhmX" ascii
    $s20 = "function bKvYSfNufzUIUtw(YexSZKsnkiUDMTQRFwd) {return parseFloat(YexSZKsnkiUDMTQRFwd);}" fullword ascii

  condition:
    uint16(0) == 0x655a and
    8 of them
}