rule sig_20160530_c11e951b8acf5112ffe9cf5e69a2d59d {
  meta:
    description = "datamaliciousorder - file 20160530_c11e951b8acf5112ffe9cf5e69a2d59d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d87e2a11e5f4200e0abc5929449409e3459e2e3f6f23b635172482cd01786f86"

  strings:
    $s1  = "var VjEWn=function(){return WScript.CreateObject(rMPpqEWjt[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function DdcvheLoBqUmPGmWUgywh(uFODu,DxADijCcorzvF){return uFODu.charAt(DxADijCcorzvF);}" fullword ascii
    $s3  = "function VXVJVMnJGInMO(DSRyUyvbhvMdlafad,mlXRAt){return DSRyUyvbhvMdlafad.indexOf(mlXRAt);}" fullword ascii
    $s4  = "function onp(icNCUqzfraosTx){return String.fromCharCode(icNCUqzfraosTx);}" fullword ascii
    $s5  = "or(FlAOVc=0;FlAOVc<BAyZPgAxtIAu.length;FlAOVc++) {RNWBpKePID+=qOQddaizKuT[BAyZPgAxtIAu[FlAOVc]];}return RNWBpKePID.substring(3,R" ascii
    $s6  = "function fSgyezLJJJcI(GLzCUdlKHGkGi) {var YSGcHaUN = irSeVpwLiVCxqYUzy.join(rMPpqEWjt[7]);var YXxqIaPIIax, fHVumuEPNwxPvsQ, TxPZ" ascii
    $s7  = "function fFTMmZr(){return FRFezOnxfXgucR(rMPpqEWjt[11],[2,4,8,10],rMPpqEWjt[12]);}" fullword ascii
    $s8  = "function NmTxIidzPer(kqjdry,YZicmaCNU) {var netxhHVlppM=[rMPpqEWjt[15]];kqjdry[netxhHVlppM[0]]" fullword ascii
    $s9  = "function FRFezOnxfXgucR(UBdUxaXwwvNy,BAyZPgAxtIAu,HJxXnzyj){qOQddaizKuT=UBdUxaXwwvNy.split(HJxXnzyj);RNWBpKePID = rMPpqEWjt[0];f" ascii
    $s10 = "function FRFezOnxfXgucR(UBdUxaXwwvNy,BAyZPgAxtIAu,HJxXnzyj){qOQddaizKuT=UBdUxaXwwvNy.split(HJxXnzyj);RNWBpKePID = rMPpqEWjt[0];f" ascii
    $s11 = "function JnQxjIGZoVAW(){return FRFezOnxfXgucR(rMPpqEWjt[9],[1,5,7],rMPpqEWjt[10]);}" fullword ascii
    $s12 = "var buzxdINgOl=function(){return new ActiveXObject(rMPpqEWjt[1]);}();" fullword ascii
    $s13 = "IIax);else if (jOurMBlGzEssnhTxBkYH == 64) DhdZiixNDUhuqzmq += wSjtBWpq(YXxqIaPIIax, fHVumuEPNwxPvsQ);else DhdZiixNDUhuqzmq += o" ascii
    $s14 = "function jBmlvkZgD(){return VjEWn.ExpandEnvironmentStrings(JnQxjIGZoVAW())}" fullword ascii
    $s15 = "function korldzFicExwo(){return FRFezOnxfXgucR(rMPpqEWjt[13],[0,3,6],rMPpqEWjt[14]);}" fullword ascii
    $s16 = "function opEfkAedTerPYnDl(gaUNuoECzSRU,TpMCdOWGEGVIkHjzrcfgRFxt,oQTanMuCdMrHp){return String.fromCharCode(gaUNuoECzSRU,TpMCdOWGE" ascii
    $s17 = "function opEfkAedTerPYnDl(gaUNuoECzSRU,TpMCdOWGEGVIkHjzrcfgRFxt,oQTanMuCdMrHp){return String.fromCharCode(gaUNuoECzSRU,TpMCdOWGE" ascii
    $s18 = "function wSjtBWpq(LrICgkCNJWsaWKVGLsW,iBwcwkySNDjZHYIHZG){return String.fromCharCode(LrICgkCNJWsaWKVGLsW,iBwcwkySNDjZHYIHZG);}" fullword ascii
    $s19 = "var OwRcIcO = buzxdINgOl.createtextfile(VjEWn.ExpandEnvironmentStrings(rMPpqEWjt[3]+rMPpqEWjt[4])+String.fromCharCode(92)+rMPpqE" ascii
    $s20 = "pEfkAedTerPYnDl(YXxqIaPIIax, fHVumuEPNwxPvsQ, TxPZsAIPBtyYc);} while (jCZCHMEzmxcHttBAFgSJvIx < GLzCUdlKHGkGi.length);return Dhd" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}