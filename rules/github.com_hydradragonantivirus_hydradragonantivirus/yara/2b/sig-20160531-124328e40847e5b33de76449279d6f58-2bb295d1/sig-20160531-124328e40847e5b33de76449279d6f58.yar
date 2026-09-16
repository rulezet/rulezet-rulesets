rule sig_20160531_124328e40847e5b33de76449279d6f58 {
  meta:
    description = "datamaliciousorder - file 20160531_124328e40847e5b33de76449279d6f58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "459ac5bf17810125054b95926c47771ca341998abc1f017198a7ad9652ffbe93"

  strings:
    $s1  = "var BiyBTKn=function(){return WScript.CreateObject(sZwDpvmfMFbNRcWYDdWDWua[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function FgYtQhtstoElvEdFrInxTQXj(ETYyndiyAXUty,wQSuczCgNesL){return ETYyndiyAXUty.charAt(wQSuczCgNesL);}" fullword ascii
    $s3  = "function qQrCMLDyqUpGNv(){return rmoXU(sZwDpvmfMFbNRcWYDdWDWua[13],[0,3,6],sZwDpvmfMFbNRcWYDdWDWua[14]);}" fullword ascii
    $s4  = "function vNfZxGvjb(OBMkZypphobkz,eKFpQGGR) {var eWtEPtT=[sZwDpvmfMFbNRcWYDdWDWua[15]];OBMkZypphobkz[eWtEPtT[0]]" fullword ascii
    $s5  = "lCmikRxOEVET(CbWIrPxVnpgKkUyjzidkcR, YpUrGhiaZzcwq);else ncidBAWGvibJjlbnwmzMUuG += NzYRchtNbeKrcXqDGxD(CbWIrPxVnpgKkUyjzidkcR, " ascii
    $s6  = "push(\"K\");nwUYsXfhFA.push(\"L\");nwUYsXfhFA.push(\"a\");nwUYsXfhFA.push(\"b\");nwUYsXfhFA.push(\"c\");nwUYsXfhFA.push(\"P\");n" ascii
    $s7  = "var EbhKGv=function(){return new ActiveXObject(sZwDpvmfMFbNRcWYDdWDWua[1]);}();" fullword ascii
    $s8  = "function yCQgzPWlYtHG(JhKljKxThkxpA) {var vfqJfd = nwUYsXfhFA.join(sZwDpvmfMFbNRcWYDdWDWua[7]);var CbWIrPxVnpgKkUyjzidkcR, YpUrG" ascii
    $s9  = "function NzYRchtNbeKrcXqDGxD(MwRxcKuRcIjbKVx,QBOCKPBsHxhSbrci,RQdEly){return String.fromCharCode(MwRxcKuRcIjbKVx,QBOCKPBsHxhSbrc" ascii
    $s10 = "function yCQgzPWlYtHG(JhKljKxThkxpA) {var vfqJfd = nwUYsXfhFA.join(sZwDpvmfMFbNRcWYDdWDWua[7]);var CbWIrPxVnpgKkUyjzidkcR, YpUrG" ascii
    $s11 = "function eO(tRcqvkMi){return String.fromCharCode(tRcqvkMi);}" fullword ascii
    $s12 = "function SyCkVkuMpPlCmikRxOEVET(bNYGoJMYjMmVix,oCrrRWNXaCB){return String.fromCharCode(bNYGoJMYjMmVix,oCrrRWNXaCB);}" fullword ascii
    $s13 = "function yCyAKydLRPGazU(){return rmoXU(sZwDpvmfMFbNRcWYDdWDWua[9],[1,5,7],sZwDpvmfMFbNRcWYDdWDWua[10]);}" fullword ascii
    $s14 = "(eKFpQGGR,0x1,0x0)}function doKMOWuQ(ALJndVPYi,YNmqBOBy,kvhzyJlxNetvV){var bnweZ=ALJndVPYi.createtextfile(YNmqBOBy,true);bnweZ.W" ascii
    $s15 = "WDWua[0];for(CvvWkJR=0;CvvWkJR<nvXkNIzZGMJcN.length;CvvWkJR++) {cEanwyroWM+=dnDBiRdtf[nvXkNIzZGMJcN[CvvWkJR]];}return cEanwyroWM" ascii
    $s16 = "function tOZonqw(){return BiyBTKn.ExpandEnvironmentStrings(yCyAKydLRPGazU())}" fullword ascii
    $s17 = "function rmoXU(kQeSoljQtpWXE,nvXkNIzZGMJcN,pvOTqttxmH){dnDBiRdtf=kQeSoljQtpWXE.split(pvOTqttxmH);cEanwyroWM = sZwDpvmfMFbNRcWYDd" ascii
    $s18 = "function xJwYc(){return rmoXU(sZwDpvmfMFbNRcWYDdWDWua[11],[2,4,8,10],sZwDpvmfMFbNRcWYDdWDWua[12]);}" fullword ascii
    $s19 = "= 64) ncidBAWGvibJjlbnwmzMUuG += eO(CbWIrPxVnpgKkUyjzidkcR);else if (PhGYpQZlmbUFMs == 64) ncidBAWGvibJjlbnwmzMUuG += SyCkVkuMpP" ascii
    $s20 = "YpUrGhiaZzcwq, lyTnVsFszvCTxxHlYwyM);} while (JiPgafpDuSmrcxPUnFjrVN < JhKljKxThkxpA.length);return ncidBAWGvibJjlbnwmzMUuG;}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}