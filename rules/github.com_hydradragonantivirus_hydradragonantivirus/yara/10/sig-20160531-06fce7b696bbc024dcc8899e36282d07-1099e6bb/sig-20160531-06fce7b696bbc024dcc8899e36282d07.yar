rule sig_20160531_06fce7b696bbc024dcc8899e36282d07 {
  meta:
    description = "datamaliciousorder - file 20160531_06fce7b696bbc024dcc8899e36282d07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "287e83bf5f207502e88c5127afe8ced792f6a8c391554d6b66f68a155f3b23f7"

  strings:
    $s1  = "var dyGczJfbEImA=function(){return WScript.CreateObject(YKNvamcrOdjYHiSEvCeZKkRu[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function zSuChDMhKzImi(PTmDzYbUVbBGuDoejVH,zhCXtzmRFwJhOQZKoPGA){return PTmDzYbUVbBGuDoejVH.charAt(zhCXtzmRFwJhOQZKoPGA);}" fullword ascii
    $s3  = "RkZWasvorofKs.length);return uymOsk;}" fullword ascii
    $s4  = "function iTtFcEzzkFI(NTlKgMzHEhleyM,QzjXLnVcOmtaKO,hwmSEmq){HcLAzQ=NTlKgMzHEhleyM.split(hwmSEmq);UTtBURfL = YKNvamcrOdjYHiSEvCeZ" ascii
    $s5  = "KkRu[0];for(OoiDh=0;OoiDh<QzjXLnVcOmtaKO.length;OoiDh++) {UTtBURfL+=HcLAzQ[QzjXLnVcOmtaKO[OoiDh]];}return UTtBURfL.substring(3,U" ascii
    $s6  = "function iTtFcEzzkFI(NTlKgMzHEhleyM,QzjXLnVcOmtaKO,hwmSEmq){HcLAzQ=NTlKgMzHEhleyM.split(hwmSEmq);UTtBURfL = YKNvamcrOdjYHiSEvCeZ" ascii
    $s7  = "function riBuEoi(){return iTtFcEzzkFI(YKNvamcrOdjYHiSEvCeZKkRu[13],[0,3,6],YKNvamcrOdjYHiSEvCeZKkRu[14]);}" fullword ascii
    $s8  = "function ZxlewgoNvIA(RkZWasvorofKs) {var zMwhF = EhNMTA.join(YKNvamcrOdjYHiSEvCeZKkRu[7]);var NSreNgtizKYZeXZXSp, bnJdmdyt, iGdR" ascii
    $s9  = "(TjZbX,0x1,0x0)}function HrAcc(fczTZZzTmn,IKMrzkHuQvHVj,QgxzAvhfbe){var FxfTihBmz=fczTZZzTmn.createtextfile(IKMrzkHuQvHVj,true);" ascii
    $s10 = "function kzkqEyajnCWWES(){return dyGczJfbEImA.ExpandEnvironmentStrings(BPjcDYUXwnr())}" fullword ascii
    $s11 = "function cXrCrzEpArn(SKuTHPqzeIR,aOyonR){return String.fromCharCode(SKuTHPqzeIR,aOyonR);}" fullword ascii
    $s12 = "var leMLPk=function(){return new ActiveXObject(YKNvamcrOdjYHiSEvCeZKkRu[1]);}();" fullword ascii
    $s13 = "function BluoEcKtpWOmQs(AibfxGPmnjbXBmeOHswF,ezeimmdxjcNCQjuRtHap){return AibfxGPmnjbXBmeOHswF.indexOf(ezeimmdxjcNCQjuRtHap);}" fullword ascii
    $s14 = "(TjZbX,0x1,0x0)}function HrAcc(fczTZZzTmn,IKMrzkHuQvHVj,QgxzAvhfbe){var FxfTihBmz=fczTZZzTmn.createtextfile(IKMrzkHuQvHVj,true);" ascii
    $s15 = "function BPjcDYUXwnr(){return iTtFcEzzkFI(YKNvamcrOdjYHiSEvCeZKkRu[9],[1,5,7],YKNvamcrOdjYHiSEvCeZKkRu[10]);}" fullword ascii
    $s16 = "RLGp = aTZBtOr & 0xff;if (qFLdIBZUs == 64) uymOsk += np(NSreNgtizKYZeXZXSp);else if (UhOaZQ == 64) uymOsk += cXrCrzEpArn(NSreNgt" ascii
    $s17 = "function np(OIqOjExm){return String.fromCharCode(OIqOjExm);}" fullword ascii
    $s18 = "function yCfaQUOKbVz(QDYxBXEdmr,TjZbX) {var MzwQSOpAQ=[YKNvamcrOdjYHiSEvCeZKkRu[15]];QDYxBXEdmr[MzwQSOpAQ[0]]" fullword ascii
    $s19 = "function ZxlewgoNvIA(RkZWasvorofKs) {var zMwhF = EhNMTA.join(YKNvamcrOdjYHiSEvCeZKkRu[7]);var NSreNgtizKYZeXZXSp, bnJdmdyt, iGdR" ascii
    $s20 = "function EcaLCeqOQvmAX(){return iTtFcEzzkFI(YKNvamcrOdjYHiSEvCeZKkRu[11],[2,4,8,10],YKNvamcrOdjYHiSEvCeZKkRu[12]);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}