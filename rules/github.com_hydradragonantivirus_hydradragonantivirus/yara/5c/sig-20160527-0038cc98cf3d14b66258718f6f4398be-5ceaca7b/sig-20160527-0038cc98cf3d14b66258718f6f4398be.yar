rule sig_20160527_0038cc98cf3d14b66258718f6f4398be {
  meta:
    description = "datamaliciousorder - file 20160527_0038cc98cf3d14b66258718f6f4398be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93e36a84d19920d600741b3af0b5cc5ca6fb9ddf0a8f9023ae3a4ea10406696b"

  strings:
    $s1  = "function WVhnjpRaA() {return WScript;}function GnPKPaaBYyS(){return sModrChtIqi.ExpandEnvironmentStrings(JYCvnToOY())}" fullword ascii
    $s2  = "function mbjZChOzya(wCGBxHTmzEPD,kRBdDfU){return wCGBxHTmzEPD.charAt(kRBdDfU);}" fullword ascii
    $s3  = "tring.fromCharCode(92)+CHeXmsuClFpjpVjHy[4],true);" fullword ascii
    $s4  = "tgoTijMbzuqHwDrzV, Vvbnbp, eYprwhaWGhxcivFCsmfAnSt);} while (OygxhTPSCHUMbLznpvP < wciSBFhlbQVsL.length);return BiBTIdXRvVledwmu" ascii
    $s5  = "function iQYdaSVog(){return XaGbbCFY(CHeXmsuClFpjpVjHy[12],[0,3,6],CHeXmsuClFpjpVjHy[13]);}" fullword ascii
    $s6  = "XqndXFOqR == 64) BiBTIdXRvVledwmuzRchIsUW += HkoEMfR(IaWtgoTijMbzuqHwDrzV, Vvbnbp);else BiBTIdXRvVledwmuzRchIsUW += TaaEXpgz(IaW" ascii
    $s7  = "function JYCvnToOY(){return XaGbbCFY(CHeXmsuClFpjpVjHy[8],[1,5,7],CHeXmsuClFpjpVjHy[9]);}" fullword ascii
    $s8  = "function XaGbbCFY(CDEPzYyapxYl,NbrSN,XysCCWrF){qttEWmioZVK=CDEPzYyapxYl.split(XysCCWrF);MMadyTAeKXSjzK = CHeXmsuClFpjpVjHy[14];f" ascii
    $s9  = "function HkoEMfR(UHLhzlRxhJmO,hqqAYV){return String.fromCharCode(UHLhzlRxhJmO,hqqAYV);}" fullword ascii
    $s10 = "function blqmodTzaLUXmnXF(IsKcOHdhk,YSNbomdbkfgz){return IsKcOHdhk.indexOf(YSNbomdbkfgz);}" fullword ascii
    $s11 = "function PVOvbBogR(ZmIYVoydTyY,GNpGwnsI) {var YQNwReZBlhMpS=[CHeXmsuClFpjpVjHy[15]];ZmIYVoydTyY[YQNwReZBlhMpS[0]](GNpGwnsI,0x1,0" ascii
    $s12 = "function vJEkUuya(wciSBFhlbQVsL) {var OLEnxEDcOxQrtSm = iTbERPJkUDepvzNvWKsGj.join(CHeXmsuClFpjpVjHy[6]);var IaWtgoTijMbzuqHwDrz" ascii
    $s13 = "function XaGbbCFY(CDEPzYyapxYl,NbrSN,XysCCWrF){qttEWmioZVK=CDEPzYyapxYl.split(XysCCWrF);MMadyTAeKXSjzK = CHeXmsuClFpjpVjHy[14];f" ascii
    $s14 = "var sModrChtIqi=function(){return WVhnjpRaA().CreateObject(CHeXmsuClFpjpVjHy[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s15 = "or(QpFqCQnHVOVVOa=0;QpFqCQnHVOVVOa<NbrSN.length;QpFqCQnHVOVVOa++) {MMadyTAeKXSjzK+=qttEWmioZVK[NbrSN[QpFqCQnHVOVVOa]];}return MM" ascii
    $s16 = "function vJEkUuya(wciSBFhlbQVsL) {var OLEnxEDcOxQrtSm = iTbERPJkUDepvzNvWKsGj.join(CHeXmsuClFpjpVjHy[6]);var IaWtgoTijMbzuqHwDrz" ascii
    $s17 = "CsmfAnSt = wxbFSP & 0xff;if (vrBvCBSlpOorioOkztQ == 64) BiBTIdXRvVledwmuzRchIsUW += sf(IaWtgoTijMbzuqHwDrzV);else if (EufXndtLDV" ascii
    $s18 = "function sf(sqwKvWcDrHmvSaQQiqd){return String.fromCharCode(sqwKvWcDrHmvSaQQiqd);}" fullword ascii
    $s19 = "function elOHeGaPAjD(){return XaGbbCFY(CHeXmsuClFpjpVjHy[10],[2,4,8,10],CHeXmsuClFpjpVjHy[11]);}" fullword ascii
    $s20 = "var tukQGDuvssNaJ=function(){return new ActiveXObject(CHeXmsuClFpjpVjHy[0]);}();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}