rule sig_20160527_1be793c5d0f131b940f2e15cd4151104 {
  meta:
    description = "datamaliciousorder - file 20160527_1be793c5d0f131b940f2e15cd4151104.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc5f06b1c5b420a3debd28ac5f06ed60f8eafe37ca09a211589c1a2180b48779"

  strings:
    $s1  = "function yvxSKD() {return WScript;}function jytku(){return lABtGfLAlhQR.ExpandEnvironmentStrings(mfHwRlFCyI())}" fullword ascii
    $s2  = "function AagkBmHJFxybyoxfflYlaXE(VmFfryIwKy,rSDgnj){return VmFfryIwKy.charAt(rSDgnj);}" fullword ascii
    $s3  = "function ZXIFZsYMZb(RHlmKRNgnAb,sRSvjc){return String.fromCharCode(RHlmKRNgnAb,sRSvjc);}" fullword ascii
    $s4  = "function wfJsdZhuxlyvnk(gjuGelek,MQPmQKmFMANBqt) {var ycjoQ=[UqmONuSt[15]];gjuGelek[ycjoQ[0]](MQPmQKmFMANBqt,0x1,0x0)}" fullword ascii
    $s5  = "function zHpEAfgDMig(coQOecfxNIhs,MkkIcwtFHwE,OnelmUq){qLoqCiJKiZrSea=coQOecfxNIhs.split(OnelmUq);htAemDYi = UqmONuSt[14];for(fk" ascii
    $s6  = " == 64) afqWDBREtFEcrEUfK += ZXIFZsYMZb(VlXaSJlivlmDuX, qjzCjtbXyHlCEbUYbKQtLeEd);else afqWDBREtFEcrEUfK += mVfkFEdyG(VlXaSJlivl" ascii
    $s7  = "mDuX, qjzCjtbXyHlCEbUYbKQtLeEd, xNxahDwZldWLUSJSfINJ);} while (MriNgNgRHLzbDOuu < jCufDXFwuGzii.length);return afqWDBREtFEcrEUfK" ascii
    $s8  = "function hDPUeRV(){return zHpEAfgDMig(UqmONuSt[12],[0,3,6],UqmONuSt[13]);}" fullword ascii
    $s9  = "var SbYgvghwNhTERA = IxEnP.createtextfile(lABtGfLAlhQR.ExpandEnvironmentStrings(UqmONuSt[2]+UqmONuSt[3])+String.fromCharCode(92)" ascii
    $s10 = "function VWcQxNLICm(jCufDXFwuGzii) {var qyRswtqrPHGQvAiExddAeV = VGmfEpEhZPWNoaLCgecMxFf.join(UqmONuSt[6]);var VlXaSJlivlmDuX, q" ascii
    $s11 = "fINJ = VvPVtWXEIHnpGmSB & 0xff;if (cKjzIUlGMKBwMrqANeYKw == 64) afqWDBREtFEcrEUfK += LY(VlXaSJlivlmDuX);else if (FTngaUPLKQlksuw" ascii
    $s12 = "oSVyKaOSMKo=0;fkoSVyKaOSMKo<MkkIcwtFHwE.length;fkoSVyKaOSMKo++) {htAemDYi+=qLoqCiJKiZrSea[MkkIcwtFHwE[fkoSVyKaOSMKo]];}return ht" ascii
    $s13 = "function mfHwRlFCyI(){return zHpEAfgDMig(UqmONuSt[8],[1,5,7],UqmONuSt[9]);}" fullword ascii
    $s14 = "function OnTrhjJTnuz(){return zHpEAfgDMig(UqmONuSt[10],[2,4,8,10],UqmONuSt[11]);}" fullword ascii
    $s15 = "function LY(QyoEiUaLizcDiG){return String.fromCharCode(QyoEiUaLizcDiG);}" fullword ascii
    $s16 = "function EQnTMQuKSIsSX(JQDjxUhzVJDtDXzickXuJhk,qUoBZfFwiUFAv){return JQDjxUhzVJDtDXzickXuJhk.indexOf(qUoBZfFwiUFAv);}" fullword ascii
    $s17 = "var lABtGfLAlhQR=function(){return yvxSKD().CreateObject(UqmONuSt[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s18 = "+UqmONuSt[4],true);" fullword ascii
    $s19 = "function VWcQxNLICm(jCufDXFwuGzii) {var qyRswtqrPHGQvAiExddAeV = VGmfEpEhZPWNoaLCgecMxFf.join(UqmONuSt[6]);var VlXaSJlivlmDuX, q" ascii
    $s20 = "function mVfkFEdyG(WNnCIytmUTGkRVb,bHTakapDaROcglMAvMB,mmidB){return String.fromCharCode(WNnCIytmUTGkRVb,bHTakapDaROcglMAvMB,mmi" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}