rule sig_20160527_9a10b41c78f05138137e9b7fef0c5d69 {
  meta:
    description = "datamaliciousorder - file 20160527_9a10b41c78f05138137e9b7fef0c5d69.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52348a9a983a94a05495ab625cb985d8d39745dc329b9795eb5a890548d79837"

  strings:
    $s1  = "function RkCynIhXH() {return WScript;}function VICNITqUlCOe(){return OMbxXAxjHPSh.ExpandEnvironmentStrings(cTtheGp())}" fullword ascii
    $s2  = "function jmmDrKIsbgZQqsae(jpSdKiWPcVIVCLDkccibgVS,JbxbL){return jpSdKiWPcVIVCLDkccibgVS.charAt(JbxbL);}" fullword ascii
    $s3  = "iwJz.length);return VkvJs;}" fullword ascii
    $s4  = "var GuItzMR=function(){return new ActiveXObject(SdBJNf[0]);}();" fullword ascii
    $s5  = "var OMbxXAxjHPSh=function(){return RkCynIhXH().CreateObject(SdBJNf[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s6  = "function SURxhEzw(DBucmiqVxiwJz) {var VZXHbAnqY = aHDzWuDAj.join(SdBJNf[6]);var wgLfNx, ltVhgrnnteUq, STSNecptAJRfYFPElwKNQu, CP" ascii
    $s7  = "function qxwDzwvIJtrc(){return zbqtEbXZQd(SdBJNf[10],[2,4,8,10],SdBJNf[11]);}" fullword ascii
    $s8  = "function zbqtEbXZQd(JoRSctIH,sTwGeIlBKTVrv,JxKKxymRu){BqkoBBsjAuT=JoRSctIH.split(JxKKxymRu);iiddKS = SdBJNf[14];for(BhUPFqma=0;B" ascii
    $s9  = "function IGiALlhKpd(ifJZTCYvQDVzLWOAl,aOTvkTlQnY,uLIAUnexyNLQGsfdLpVEH){return String.fromCharCode(ifJZTCYvQDVzLWOAl,aOTvkTlQnY," ascii
    $s10 = "function MeMAdbKT(EIkyRassTFbVOm,TMIst){return String.fromCharCode(EIkyRassTFbVOm,TMIst);}" fullword ascii
    $s11 = "function EwvkKhOZlZujUu(){return zbqtEbXZQd(SdBJNf[12],[0,3,6],SdBJNf[13]);}" fullword ascii
    $s12 = "Nx, ltVhgrnnteUq);else VkvJs += IGiALlhKpd(wgLfNx, ltVhgrnnteUq, STSNecptAJRfYFPElwKNQu);} while (AyIFeJIplcKBseCysb < DBucmiqVx" ascii
    $s13 = "function IGiALlhKpd(ifJZTCYvQDVzLWOAl,aOTvkTlQnY,uLIAUnexyNLQGsfdLpVEH){return String.fromCharCode(ifJZTCYvQDVzLWOAl,aOTvkTlQnY," ascii
    $s14 = "hUPFqma<sTwGeIlBKTVrv.length;BhUPFqma++) {iiddKS+=BqkoBBsjAuT[sTwGeIlBKTVrv[BhUPFqma]];}return iiddKS.substring(3,iiddKS.length)" ascii
    $s15 = "function zbqtEbXZQd(JoRSctIH,sTwGeIlBKTVrv,JxKKxymRu){BqkoBBsjAuT=JoRSctIH.split(JxKKxymRu);iiddKS = SdBJNf[14];for(BhUPFqma=0;B" ascii
    $s16 = "function cTtheGp(){return zbqtEbXZQd(SdBJNf[8],[1,5,7],SdBJNf[9]);}" fullword ascii
    $s17 = "JRfYFPElwKNQu = VVSBtPW & 0xff;if (OrTINjZXqTrsDtVONvGN == 64) VkvJs += Sb(wgLfNx);else if (EdEmfY == 64) VkvJs += MeMAdbKT(wgLf" ascii
    $s18 = "function Sb(rNXxbNcuUEhXaw){return String.fromCharCode(rNXxbNcuUEhXaw);}" fullword ascii
    $s19 = "var zUOfSPv = GuItzMR.createtextfile(OMbxXAxjHPSh.ExpandEnvironmentStrings(SdBJNf[2]+SdBJNf[3])+String.fromCharCode(92)+SdBJNf[4" ascii
    $s20 = "],true);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}