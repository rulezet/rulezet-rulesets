rule sig_20151217_16305ca2d281a5df7a9c1c7b0206b25e {
  meta:
    description = "datamaliciousorder - file 20151217_16305ca2d281a5df7a9c1c7b0206b25e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa4b161373e5107302e286d83d0a41b8721301c484e342cbed6ed21be8832294"

  strings:
    $s1  = "pow(Math.cos(230), 2) - 1)));} HNxnLUirq[kaPJYgZllhm]++;}kaPJYgZllhm++;} return aaPRISopCCg}" fullword ascii
    $s2  = "th.pow(Math.cos(874), 2) - 1)); while(true) { if(HNxnLUirq[kaPJYgZllhm] > VMLGF[kaPJYgZllhm].length-(-274+948)/674) { break; } i" ascii
    $s3  = ") - 1));while(true){if (kaPJYgZllhm >= (3035+769)/634){break;}HNxnLUirq[kaPJYgZllhm]=Math.round((Math.pow(Math.sin(874), 2) + Ma" ascii
    $s4  = "function VTnFaABNpPWYIKNEn(VMLGF){aaPRISopCCg= '';kaPJYgZllhm=Math.round((Math.pow(Math.sin(330), 2) + Math.pow(Math.cos(330), 2" ascii
    $s5  = "SYTlWbphkIYBJaaXMuOPuOhnmpGqoyqIjoA([VMLGF[kaPJYgZllhm][HNxnLUirq[kaPJYgZllhm]]], Math.round((Math.pow(Math.sin(230), 2) + Math." ascii
    $s6  = "function VTnFaABNpPWYIKNEn(VMLGF){aaPRISopCCg= '';kaPJYgZllhm=Math.round((Math.pow(Math.sin(330), 2) + Math.pow(Math.cos(330), 2" ascii
    $s7  = "function FndxpAN(taGeZoZWJDarBbByyCRpKBBCyCpqJVHiqCJg) {return !cSwtPxkHpHo(OudwikmRxQlNjnV(taGeZoZWJDarBbByyCRpKBBCyCpqJVHiqCJg" ascii
    $s8  = "var U = new Array();U[0]=[];U[0][0]='d';U[0][1]='a';U[0][2]='d';U[0][3]='a';U[0][4]='46';U[0][5]='3d';U[0][6]='42';U[0][7]='14';" ascii
    $s9  = "function ksBgGeUnVHwuYFB(nhOnxwwDcjlxJHDlc,XHUlWApGIYWhplSpxQRiGrauggWqBHqRdL,SlQeiihSIojHONFVIIMWSwnznZXxRcEJnSo){eval(nhOnxwwD" ascii
    $s10 = "function ZwWap(MROdJrVvODs,UgAhyLnnXpNcC,OkIxVXKq){trFj=niBVBiIBFhKnNOXsj(MROdJrVvODs,UgAhyLnnXpNcC);jqMWe=trFj.toString(OkIxVXK" ascii
    $s11 = "var U = new Array();U[0]=[];U[0][0]='d';U[0][1]='a';U[0][2]='d';U[0][3]='a';U[0][4]='46';U[0][5]='3d';U[0][6]='42';U[0][7]='14';" ascii
    $s12 = "function OudwikmRxQlNjnV(IDGxLSZPwoOyGLCXJZo) {return parseFloat(IDGxLSZPwoOyGLCXJZo);}" fullword ascii
    $s13 = "function ksBgGeUnVHwuYFB(nhOnxwwDcjlxJHDlc,XHUlWApGIYWhplSpxQRiGrauggWqBHqRdL,SlQeiihSIojHONFVIIMWSwnznZXxRcEJnSo){eval(nhOnxwwD" ascii
    $s14 = "function cSwtPxkHpHo(llVrrPSzzPjAst) {return isNaN(llVrrPSzzPjAst);}" fullword ascii
    $s15 = "function niBVBiIBFhKnNOXsj(sPmdVOxRUx,TdyMUkIOrL) {return parseInt(sPmdVOxRUx,TdyMUkIOrL);}" fullword ascii
    $s16 = "function ZwWap(MROdJrVvODs,UgAhyLnnXpNcC,OkIxVXKq){trFj=niBVBiIBFhKnNOXsj(MROdJrVvODs,UgAhyLnnXpNcC);jqMWe=trFj.toString(OkIxVXK" ascii
    $s17 = "function M(HkBLSaIHfkzw,XDlvKpbPgseFsP){HkBLSaIHfkzw.push(XDlvKpbPgseFsP);}" fullword ascii
    $s18 = "function hNgqrXgiaxMg(pVLwLwkUnMtjg) {return isFinite(pVLwLwkUnMtjg);}" fullword ascii
    $s19 = "function FndxpAN(taGeZoZWJDarBbByyCRpKBBCyCpqJVHiqCJg) {return !cSwtPxkHpHo(OudwikmRxQlNjnV(taGeZoZWJDarBbByyCRpKBBCyCpqJVHiqCJg" ascii
    $s20 = "function f(xPsqGbRsgBXrva,kVdxdZUzvasXX,xDMvnaWHPWI) {xPsqGbRsgBXrva[kVdxdZUzvasXX]=xDMvnaWHPWI;}" fullword ascii

  condition:
    uint16(0) == 0x714e and
    8 of them
}