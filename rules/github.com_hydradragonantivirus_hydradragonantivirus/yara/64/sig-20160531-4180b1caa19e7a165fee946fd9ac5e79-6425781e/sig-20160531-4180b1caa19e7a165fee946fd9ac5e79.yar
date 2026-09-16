rule sig_20160531_4180b1caa19e7a165fee946fd9ac5e79 {
  meta:
    description = "datamaliciousorder - file 20160531_4180b1caa19e7a165fee946fd9ac5e79.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7409cdfa837ca15795225852f9aa3d50d23fbe1e6391fa3bd030e54785808f32"

  strings:
    $s1  = "var SCRkv=function(){return WScript.CreateObject(avSWXBFWTdDWaKFxiES[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function AydKrhv(DRYMORqmazDQnRnohgOgo,xlVspaYuSzdDFeczxeRuO){return DRYMORqmazDQnRnohgOgo.charAt(xlVspaYuSzdDFeczxeRuO);}" fullword ascii
    $s3  = "(qtzfHGauZCP,0x1,0x0)}function VJURg(hxRwnCyGcKdyu,lCOxkHme,ulrOnjmdT){var SdxzQ=hxRwnCyGcKdyu.createtextfile(lCOxkHme,true);Sdx" ascii
    $s4  = "function EhWnDTXhBTBxD(DzqQOfVupPhZjvH,WoQTl,RYQvpnPGwsPhyCoKWG){return String.fromCharCode(DzqQOfVupPhZjvH,WoQTl,RYQvpnPGwsPhyC" ascii
    $s5  = "HSVviBkz<sgZOmmqQSthCt.length;HSVviBkz++) {kMkKzn+=QCCPqkbCzJk[sgZOmmqQSthCt[HSVviBkz]];}return kMkKzn.substring(3,kMkKzn.length" ascii
    $s6  = ";zNZqhrgKoAXakfrPCDR = xZfpMQEqlPW & 0xff;if (rhdfiCDCOSsGnOPXpMEqulQ == 64) ZvktkuiwnYN += kR(yaZwIO);else if (EAEAPsjBGdZvkpgA" ascii
    $s7  = "function KgIkklEQBOwQ(gthRUWkWuOJBm) {var kbBbjddrutHLrXsAsu = xtHFYbEvQFX.join(avSWXBFWTdDWaKFxiES[7]);var yaZwIO, kvjyRp, zNZq" ascii
    $s8  = "(LzbNDFzir < gthRUWkWuOJBm.length);return ZvktkuiwnYN;}" fullword ascii
    $s9  = "function KgIkklEQBOwQ(gthRUWkWuOJBm) {var kbBbjddrutHLrXsAsu = xtHFYbEvQFX.join(avSWXBFWTdDWaKFxiES[7]);var yaZwIO, kvjyRp, zNZq" ascii
    $s10 = "V == 64) ZvktkuiwnYN += EKVRyclu(yaZwIO, kvjyRp);else ZvktkuiwnYN += EhWnDTXhBTBxD(yaZwIO, kvjyRp, zNZqhrgKoAXakfrPCDR);} while " ascii
    $s11 = "function RAIuIUAO(){return SCRkv.ExpandEnvironmentStrings(sGzaNxetDno())}" fullword ascii
    $s12 = "function EKVRyclu(MPrHTSXujTMLw,prNZSesEinsiuX){return String.fromCharCode(MPrHTSXujTMLw,prNZSesEinsiuX);}" fullword ascii
    $s13 = "function EhWnDTXhBTBxD(DzqQOfVupPhZjvH,WoQTl,RYQvpnPGwsPhyCoKWG){return String.fromCharCode(DzqQOfVupPhZjvH,WoQTl,RYQvpnPGwsPhyC" ascii
    $s14 = "function dkbsKwMedhg(RCnKMlwJhQymJjl,ihfjnhLMQbWzOXnX){return RCnKMlwJhQymJjl.indexOf(ihfjnhLMQbWzOXnX);}" fullword ascii
    $s15 = "function kR(DAKQnedMPoQ){return String.fromCharCode(DAKQnedMPoQ);}" fullword ascii
    $s16 = "function svSYwjMt(lJGjfWxsFrVQ,qtzfHGauZCP) {var DGxAznfDbQVmK=[avSWXBFWTdDWaKFxiES[15]];lJGjfWxsFrVQ[DGxAznfDbQVmK[0]]" fullword ascii
    $s17 = "var osvnZXJtSA=function(){return new ActiveXObject(avSWXBFWTdDWaKFxiES[1]);}();" fullword ascii
    $s18 = "(qtzfHGauZCP,0x1,0x0)}function VJURg(hxRwnCyGcKdyu,lCOxkHme,ulrOnjmdT){var SdxzQ=hxRwnCyGcKdyu.createtextfile(lCOxkHme,true);Sdx" ascii
    $s19 = "function KcArlYezW(LOruvdf,sgZOmmqQSthCt,AwAzv){QCCPqkbCzJk=LOruvdf.split(AwAzv);kMkKzn = avSWXBFWTdDWaKFxiES[0];for(HSVviBkz=0;" ascii
    $s20 = "function sGzaNxetDno(){return KcArlYezW(avSWXBFWTdDWaKFxiES[9],[1,5,7],avSWXBFWTdDWaKFxiES[10]);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}