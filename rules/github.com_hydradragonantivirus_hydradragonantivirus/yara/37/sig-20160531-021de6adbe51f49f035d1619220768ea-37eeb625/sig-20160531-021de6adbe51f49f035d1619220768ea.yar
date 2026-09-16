rule sig_20160531_021de6adbe51f49f035d1619220768ea {
  meta:
    description = "datamaliciousorder - file 20160531_021de6adbe51f49f035d1619220768ea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "edc447329859f973e9bd33681b18f29877e3ec4e0523e273c7d6ae7a944d157d"

  strings:
    $s1  = "var Qsrcx=function(){return WScript.CreateObject(cHudizyk[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function VEtNWkOaulYszpCpNwRFnmEf(pbREZXHfpRwzLHvESdaNa,KGTydf){return pbREZXHfpRwzLHvESdaNa.charAt(KGTydf);}" fullword ascii
    $s3  = "(YIFcFKFKq,0x1,0x0)}function xZekHOXDdY(QqkGWURrbvDvZz,keYsbJGH,tYzNhy){var DKNweDGrNQxyk=QqkGWURrbvDvZz.createtextfile(keYsbJGH" ascii
    $s4  = "(YIFcFKFKq,0x1,0x0)}function xZekHOXDdY(QqkGWURrbvDvZz,keYsbJGH,tYzNhy){var DKNweDGrNQxyk=QqkGWURrbvDvZz.createtextfile(keYsbJGH" ascii
    $s5  = "function QZfnhLgLrRTDFUHkZ(uFighKoWbSJLwbJYPMucjddL,bjYYbWdv){return uFighKoWbSJLwbJYPMucjddL.indexOf(bjYYbWdv);}" fullword ascii
    $s6  = "function mK(iBgRRX){return String.fromCharCode(iBgRRX);}" fullword ascii
    $s7  = "= mK(QBURDmRlCM);else if (LZqGAcSpJSmtQzEH == 64) qSCEhfnVlnaE += SNTRjRaQUmsEr(QBURDmRlCM, RPvLGrYgFwAF);else qSCEhfnVlnaE += l" ascii
    $s8  = "function OSFaxtiSUQT(){return lHViebaUb(cHudizyk[11],[2,4,8,10],cHudizyk[12]);}" fullword ascii
    $s9  = "function ksxtIP(SACYaiNpKHsLq) {var SPnvo = ijBTCPfiApSzhCqaXfW.join(cHudizyk[7]);var QBURDmRlCM, RPvLGrYgFwAF, pbfgffrnZcSTbDEz" ascii
    $s10 = "function LWdtTBuqZZbUVu(){return lHViebaUb(cHudizyk[13],[0,3,6],cHudizyk[14]);}" fullword ascii
    $s11 = "function DasOPNqCpCiA(){return Qsrcx.ExpandEnvironmentStrings(XfZOJoSC())}" fullword ascii
    $s12 = "function ksxtIP(SACYaiNpKHsLq) {var SPnvo = ijBTCPfiApSzhCqaXfW.join(cHudizyk[7]);var QBURDmRlCM, RPvLGrYgFwAF, pbfgffrnZcSTbDEz" ascii
    $s13 = "function lwfmpDKdpjiMFuPrrnEoeG(JFAObgOwTunawjxoMrjznVEq,hDKoxuYgN,jsDILtNViCduqNcRZG){return String.fromCharCode(JFAObgOwTunawj" ascii
    $s14 = "function lHViebaUb(dflrVFyf,tjXsvgtzGQgo,JWvSEU){IJCQBpXrr=dflrVFyf.split(JWvSEU);UJaxDnuj = cHudizyk[0];for(saAhGBnTuT=0;saAhGB" ascii
    $s15 = "nTuT<tjXsvgtzGQgo.length;saAhGBnTuT++) {UJaxDnuj+=IJCQBpXrr[tjXsvgtzGQgo[saAhGBnTuT]];}return UJaxDnuj.substring(3,UJaxDnuj.leng" ascii
    $s16 = "function iXOxScRYaro(IKGlYKWldPe,YIFcFKFKq) {var juMSGmntpcd=[cHudizyk[15]];IKGlYKWldPe[juMSGmntpcd[0]]" fullword ascii
    $s17 = "function lHViebaUb(dflrVFyf,tjXsvgtzGQgo,JWvSEU){IJCQBpXrr=dflrVFyf.split(JWvSEU);UJaxDnuj = cHudizyk[0];for(saAhGBnTuT=0;saAhGB" ascii
    $s18 = "wfmpDKdpjiMFuPrrnEoeG(QBURDmRlCM, RPvLGrYgFwAF, pbfgffrnZcSTbDEzdj);} while (ISCEglyOXHMCTqCxXyhbwEu < SACYaiNpKHsLq.length);ret" ascii
    $s19 = "var xkWMS=function(){return new ActiveXObject(cHudizyk[1]);}();" fullword ascii
    $s20 = "function XfZOJoSC(){return lHViebaUb(cHudizyk[9],[1,5,7],cHudizyk[10]);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}