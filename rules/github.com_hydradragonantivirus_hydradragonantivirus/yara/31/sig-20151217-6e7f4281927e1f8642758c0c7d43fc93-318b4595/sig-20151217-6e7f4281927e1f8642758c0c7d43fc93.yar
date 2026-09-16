rule sig_20151217_6e7f4281927e1f8642758c0c7d43fc93 {
  meta:
    description = "datamaliciousorder - file 20151217_6e7f4281927e1f8642758c0c7d43fc93.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eec41e5c07c16442633ff7d1016f24087c7a1a116f444bdcc1bd1719447cc8e7"

  strings:
    $s1  = "ath.cos(733), 2) - 1)));} OshoHfblF[wJScOlsszRh]++;}wJScOlsszRh++;} return eUgqOmLBQKg}" fullword ascii
    $s2  = "pow(Math.cos(841), 2) - 1)); while(true) { if(OshoHfblF[wJScOlsszRh] > hrdKB[wJScOlsszRh].length-(51+854)/905) { break; } if (RV" ascii
    $s3  = "function hDZMPmBlmDUneJBDi(hrdKB){eUgqOmLBQKg= '';wJScOlsszRh=Math.round((Math.pow(Math.sin(49), 2) + Math.pow(Math.cos(49), 2) " ascii
    $s4  = "function hDZMPmBlmDUneJBDi(hrdKB){eUgqOmLBQKg= '';wJScOlsszRh=Math.round((Math.pow(Math.sin(49), 2) + Math.pow(Math.cos(49), 2) " ascii
    $s5  = "- 1));while(true){if (wJScOlsszRh >= (624+492)/186){break;}OshoHfblF[wJScOlsszRh]=Math.round((Math.pow(Math.sin(841), 2) + Math." ascii
    $s6  = "function RVobIpz(tMYbGCTnqQygcEDSXoPWdClDStJDzrpOKztz) {return !XOCyjLPZzsj(UKROmGIvehddBPB(tMYbGCTnqQygcEDSXoPWdClDStJDzrpOKztz" ascii
    $s7  = "var a = new Array();a[0]=[];a[0][0]='d';a[0][1]='a';a[0][2]='d';a[0][3]='a';a[0][4]='46';a[0][5]='3d';a[0][6]='42';a[0][7]='14';" ascii
    $s8  = "function nYgGUdJPANkWxsiyoGrTNDWdwWgAykfokdBoapOmteDrwnnyysxegc(cCnvVecrUisDf,zKeWyZkcevPGco){ return SjngTbN[UtOnuosO[XxqQm(cCn" ascii
    $s9  = "var a = new Array();a[0]=[];a[0][0]='d';a[0][1]='a';a[0][2]='d';a[0][3]='a';a[0][4]='46';a[0][5]='3d';a[0][6]='42';a[0][7]='14';" ascii
    $s10 = "function D(zKaciAwudHNO,ctdMfTZlqcKzsA){zKaciAwudHNO.push(ctdMfTZlqcKzsA);}" fullword ascii
    $s11 = "function VPabRkxCSONM(QjbCYVpbpxhHw) {return isFinite(QjbCYVpbpxhHw);}" fullword ascii
    $s12 = "function XOCyjLPZzsj(RPkOHqUKSXtqYC) {return isNaN(RPkOHqUKSXtqYC);}" fullword ascii
    $s13 = "function MVDtogdKbKjdbjUke(DOMoSvMkXl,KKxevYwbWT) {return parseInt(DOMoSvMkXl,KKxevYwbWT);}" fullword ascii
    $s14 = "q);return rNeCs;}" fullword ascii
    $s15 = "function nYgGUdJPANkWxsiyoGrTNDWdwWgAykfokdBoapOmteDrwnnyysxegc(cCnvVecrUisDf,zKeWyZkcevPGco){ return SjngTbN[UtOnuosO[XxqQm(cCn" ascii
    $s16 = "function H(VZjuCMgiGQrgzo,jiQjgHRGTkFFu,QoFZGodCVjE) {VZjuCMgiGQrgzo[jiQjgHRGTkFFu]=QoFZGodCVjE;}" fullword ascii
    $s17 = "function RVobIpz(tMYbGCTnqQygcEDSXoPWdClDStJDzrpOKztz) {return !XOCyjLPZzsj(UKROmGIvehddBPB(tMYbGCTnqQygcEDSXoPWdClDStJDzrpOKztz" ascii
    $s18 = "function UKROmGIvehddBPB(WJYpPMEuGQtrtsBnGkS) {return parseFloat(WJYpPMEuGQtrtsBnGkS);}" fullword ascii
    $s19 = "function XxqQm(WfqaYLeORfA,scATYULWisUbS,ZdHaYZnq){noBi=MVDtogdKbKjdbjUke(WfqaYLeORfA,scATYULWisUbS);rNeCs=noBi.toString(ZdHaYZn" ascii
    $s20 = "function jeAWwkpOQebBznc(bFCaGxqXARYdkSfFC,tIJITCkGhuPyMGInqQlBjbzcSmRiWmgbOh,HMlZcMkLKKNMbTKaAwLectFPbBAsTsniwEi){eval(bFCaGxqX" ascii

  condition:
    uint16(0) == 0x7455 and
    8 of them
}