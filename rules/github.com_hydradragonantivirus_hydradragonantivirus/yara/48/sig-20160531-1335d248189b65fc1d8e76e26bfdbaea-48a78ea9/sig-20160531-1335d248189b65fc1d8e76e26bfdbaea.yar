rule sig_20160531_1335d248189b65fc1d8e76e26bfdbaea {
  meta:
    description = "datamaliciousorder - file 20160531_1335d248189b65fc1d8e76e26bfdbaea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce4b6cb5c2ccfe0a212ce0ae11f73d98975bf0a9f7e21e1d8c8124f5a0d9690c"

  strings:
    $s1  = "var sTFsJbsZC=function(){return WScript.CreateObject(aHGxrZJgapc[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function DWKBLvVfLwjbKnpIJOq(ZAJWsiGoOdGcrAMOZAbPn,aTrMBNd){return ZAJWsiGoOdGcrAMOZAbPn.charAt(aTrMBNd);}" fullword ascii
    $s3  = "function uWafGjOkmQbpDHBtBDLpWKt(DaTHXzfoSLoMXHStiTwgW,pFHMGsYO,hyoHbTImTGW){return String.fromCharCode(DaTHXzfoSLoMXHStiTwgW,pF" ascii
    $s4  = "function aTvRirFEWCdyN(JjPhQ,PTJEHWtOhREqwy,TiUJWKlYwgXG){WRpJpLyFyuIMe=JjPhQ.split(TiUJWKlYwgXG);UAtleoTH = aHGxrZJgapc[0];for(" ascii
    $s5  = "(CyrPb,0x1,0x0)}function bvCRrI(khsCFfoPqbrXOG,HYGtEuUYGWWBJR,yGtfXTWn){var CfpUKBSRf=khsCFfoPqbrXOG.createtextfile(HYGtEuUYGWWB" ascii
    $s6  = "ZSuz < KwJRPpwifSfBe.length);return vFWzTD;}" fullword ascii
    $s7  = "function fqujPkHf(){return aTvRirFEWCdyN(aHGxrZJgapc[9],[1,5,7],aHGxrZJgapc[10]);}" fullword ascii
    $s8  = "function ehAfgD(){return aTvRirFEWCdyN(aHGxrZJgapc[13],[0,3,6],aHGxrZJgapc[14]);}" fullword ascii
    $s9  = "var tjuvDhvmorm=function(){return new ActiveXObject(aHGxrZJgapc[1]);}();" fullword ascii
    $s10 = "function TKkmIphVLz(AWiFttxthPhIe,CyrPb) {var DJuaucE=[aHGxrZJgapc[15]];AWiFttxthPhIe[DJuaucE[0]]" fullword ascii
    $s11 = "function yTOPvwNzLnC(){return sTFsJbsZC.ExpandEnvironmentStrings(fqujPkHf())}" fullword ascii
    $s12 = "function S(kXpAzmUHOjjsfl){return String.fromCharCode(kXpAzmUHOjjsfl);}" fullword ascii
    $s13 = "function FbyES(){return aTvRirFEWCdyN(aHGxrZJgapc[11],[2,4,8,10],aHGxrZJgapc[12]);}" fullword ascii
    $s14 = "function ZNtayvEHzTGFAggz(YQxpIqOHGdmVCfMtTo,oKZxvDggQcXqzzDnsHDs){return String.fromCharCode(YQxpIqOHGdmVCfMtTo,oKZxvDggQcXqzzD" ascii
    $s15 = "function uWafGjOkmQbpDHBtBDLpWKt(DaTHXzfoSLoMXHStiTwgW,pFHMGsYO,hyoHbTImTGW){return String.fromCharCode(DaTHXzfoSLoMXHStiTwgW,pF" ascii
    $s16 = "function dkNsY(KwJRPpwifSfBe) {var gasxSuqBUtIzIKPeVbEuo = mTAiOukSLHYNUwOGAJLN.join(aHGxrZJgapc[7]);var ZppYTbnQUUNBlmkaYFqwYcg" ascii
    $s17 = "ppYTbnQUUNBlmkaYFqwYcg);else if (WUMZqKhIjCqoHpU == 64) vFWzTD += ZNtayvEHzTGFAggz(ZppYTbnQUUNBlmkaYFqwYcg, NnPxvuUMGboORsbJwhRk" ascii
    $s18 = "Mnh);else vFWzTD += uWafGjOkmQbpDHBtBDLpWKt(ZppYTbnQUUNBlmkaYFqwYcg, NnPxvuUMGboORsbJwhRkMnh, pmUAQa);} while (gACWOfqBcUjvijrSL" ascii
    $s19 = "function aTvRirFEWCdyN(JjPhQ,PTJEHWtOhREqwy,TiUJWKlYwgXG){WRpJpLyFyuIMe=JjPhQ.split(TiUJWKlYwgXG);UAtleoTH = aHGxrZJgapc[0];for(" ascii
    $s20 = "JR,true);CfpUKBSRf.WriteLine(yGtfXTWn);CfpUKBSRf.Close();}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}