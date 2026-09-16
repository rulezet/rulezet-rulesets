rule sig_20160531_95993e50d51e09856f29b88173fa22ae {
  meta:
    description = "datamaliciousorder - file 20160531_95993e50d51e09856f29b88173fa22ae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dfaca44bedec2d44c3c7b135be689cb9f053deabe66179b39a6d72345d8a3e5e"

  strings:
    $s1  = "var jQqPZOlfvYc=function(){return WScript.CreateObject(BNRkI[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function EYaCiXvKdaZe(qOYMivMaWuJrNyjvQJEY,CMKpZ){return qOYMivMaWuJrNyjvQJEY.charAt(CMKpZ);}" fullword ascii
    $s3  = "(dUvyyS,0x1,0x0)}function nzcvbcXrwnNJ(lVUFpf,hwXfLPpr,itcNCEO){var KjKyJUMcV=lVUFpf.createtextfile(hwXfLPpr,true);KjKyJUMcV.Wri" ascii
    $s4  = "function shwDtpnCerqfrXsZchhs(aOMiQAYoGPlSuPvVp,hHQLJOFktFFqMkTXGUvNI,khAQQvqqsiRXuQrrESJcLj){return String.fromCharCode(aOMiQAY" ascii
    $s5  = "function wpxnVYivcwkbLB(mFmiuTtvAIBOEB,dUvyyS) {var bcRohkFDSAK=[BNRkI[15]];mFmiuTtvAIBOEB[bcRohkFDSAK[0]]" fullword ascii
    $s6  = "function XiIpZdFaaGD(){return rpUqDQAkjx(BNRkI[13],[0,3,6],BNRkI[14]);}" fullword ascii
    $s7  = "pfWSL<RIoheethXIt.length;pfWSL++) {lMQAdMajMh+=vGzNgEcIi[RIoheethXIt[pfWSL]];}return lMQAdMajMh.substring(3,lMQAdMajMh.length);}" ascii
    $s8  = "function ooGihJk(hHyFzCwUArFYx) {var aSOPeWaUsqXsfOwKXOZDxnS = NRgOILXxcmtn.join(BNRkI[7]);var EnnTbCt, vhxERhn, JnvJGyCZ, HMzNk" ascii
    $s9  = "function rpUqDQAkjx(mwpQzSUKG,RIoheethXIt,CTpxIibKkQi){vGzNgEcIi=mwpQzSUKG.split(CTpxIibKkQi);lMQAdMajMh = BNRkI[0];for(pfWSL=0;" ascii
    $s10 = "function shwDtpnCerqfrXsZchhs(aOMiQAYoGPlSuPvVp,hHQLJOFktFFqMkTXGUvNI,khAQQvqqsiRXuQrrESJcLj){return String.fromCharCode(aOMiQAY" ascii
    $s11 = "var wqybM=function(){return new ActiveXObject(BNRkI[1]);}();" fullword ascii
    $s12 = "function grTZutiUkMEgZhZuvpWBr(TcnCrhVsPNicJGB,OiPccpIioCjGBma){return String.fromCharCode(TcnCrhVsPNicJGB,OiPccpIioCjGBma);}" fullword ascii
    $s13 = "(dUvyyS,0x1,0x0)}function nzcvbcXrwnNJ(lVUFpf,hwXfLPpr,itcNCEO){var KjKyJUMcV=lVUFpf.createtextfile(hwXfLPpr,true);KjKyJUMcV.Wri" ascii
    $s14 = "function gnWAqrzWgZnKz(){return jQqPZOlfvYc.ExpandEnvironmentStrings(sOAUlQwXrJrXN())}" fullword ascii
    $s15 = "FOcLhGxj == 64) bjuCmvJx += RJ(EnnTbCt);else if (TjJVVdCKVn == 64) bjuCmvJx += grTZutiUkMEgZhZuvpWBr(EnnTbCt, vhxERhn);else bjuC" ascii
    $s16 = "mvJx += shwDtpnCerqfrXsZchhs(EnnTbCt, vhxERhn, JnvJGyCZ);} while (TSlKVaygzON < hHyFzCwUArFYx.length);return bjuCmvJx;}" fullword ascii
    $s17 = "function rpUqDQAkjx(mwpQzSUKG,RIoheethXIt,CTpxIibKkQi){vGzNgEcIi=mwpQzSUKG.split(CTpxIibKkQi);lMQAdMajMh = BNRkI[0];for(pfWSL=0;" ascii
    $s18 = "function RJ(KZexowlDZrUVzuZPexOk){return String.fromCharCode(KZexowlDZrUVzuZPexOk);}" fullword ascii
    $s19 = "function zAtzCHsh(){return rpUqDQAkjx(BNRkI[11],[2,4,8,10],BNRkI[12]);}" fullword ascii
    $s20 = "function ooGihJk(hHyFzCwUArFYx) {var aSOPeWaUsqXsfOwKXOZDxnS = NRgOILXxcmtn.join(BNRkI[7]);var EnnTbCt, vhxERhn, JnvJGyCZ, HMzNk" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}