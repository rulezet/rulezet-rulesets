rule sig_20160530_6481b966611e28e90ed72138b234ac68 {
  meta:
    description = "datamaliciousorder - file 20160530_6481b966611e28e90ed72138b234ac68.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2436139c683edff980e0b7c96dc615f760ed50ee643452d3e8956f092c17542b"

  strings:
    $s1  = "var nAhqZYoLrNjZxd=function(){return WScript.CreateObject(nIEZPWjUtyawwcldVOhxs[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function mFlcc(gGBGfTwIfowlONICfEHfkU,lwPofZivUksFep){return gGBGfTwIfowlONICfEHfkU.charAt(lwPofZivUksFep);}" fullword ascii
    $s3  = "function zIYpDsMvPc(){return UhhYVIFRD(nIEZPWjUtyawwcldVOhxs[11],[2,4,8,10],nIEZPWjUtyawwcldVOhxs[12]);}" fullword ascii
    $s4  = "=0;seCKelpafkh<mIRACS.length;seCKelpafkh++) {aLtvILxKd+=VmGpa[mIRACS[seCKelpafkh]];}return aLtvILxKd.substring(3,aLtvILxKd.lengt" ascii
    $s5  = "function iRTZfGev(SjhfrvfOhFjCe) {var TMMFUgeDe = uTGhlJENq.join(nIEZPWjUtyawwcldVOhxs[7]);var qCbQgMSMJteSueBThAbjFAi, zjbHBBKT" ascii
    $s6  = "var QPpWxZeEXfgSME = JkTWIUL.createtextfile(nAhqZYoLrNjZxd.ExpandEnvironmentStrings(nIEZPWjUtyawwcldVOhxs[3]+nIEZPWjUtyawwcldVOh" ascii
    $s7  = "function VeBSyTH(PxUmGynuORBwHhfAGDRc,SEvxqbx,VYUdRGOlRkSXVvIYPSEAv){return String.fromCharCode(PxUmGynuORBwHhfAGDRc,SEvxqbx,VYU" ascii
    $s8  = "var JkTWIUL=function(){return new ActiveXObject(nIEZPWjUtyawwcldVOhxs[1]);}();" fullword ascii
    $s9  = "(qCbQgMSMJteSueBThAbjFAi, zjbHBBKTwSyJe);else RwRrJjo += VeBSyTH(qCbQgMSMJteSueBThAbjFAi, zjbHBBKTwSyJe, pHBBQLRygkItbGvRWwImGhn" ascii
    $s10 = "function TlQSDyp(){return UhhYVIFRD(nIEZPWjUtyawwcldVOhxs[9],[1,5,7],nIEZPWjUtyawwcldVOhxs[10]);}" fullword ascii
    $s11 = "KueeHT & 0xff;if (HokfUOePrBgtWhemBen == 64) RwRrJjo += WTj(qCbQgMSMJteSueBThAbjFAi);else if (pOJrUot == 64) RwRrJjo += rjpXOiyP" ascii
    $s12 = "xs[4])+String.fromCharCode(92)+nIEZPWjUtyawwcldVOhxs[5],true);" fullword ascii
    $s13 = "function qftqLwPaAmMB(){return UhhYVIFRD(nIEZPWjUtyawwcldVOhxs[13],[0,3,6],nIEZPWjUtyawwcldVOhxs[14]);}" fullword ascii
    $s14 = "function Ecfnjbs(XGnmyAmboOMN,azEchv){return XGnmyAmboOMN.indexOf(azEchv);}" fullword ascii
    $s15 = "F);} while (MkRkVPXX < SjhfrvfOhFjCe.length);return RwRrJjo;}" fullword ascii
    $s16 = "function UhhYVIFRD(QAGxq,mIRACS,vsjwISoviVq){VmGpa=QAGxq.split(vsjwISoviVq);aLtvILxKd = nIEZPWjUtyawwcldVOhxs[0];for(seCKelpafkh" ascii
    $s17 = "function UhhYVIFRD(QAGxq,mIRACS,vsjwISoviVq){VmGpa=QAGxq.split(vsjwISoviVq);aLtvILxKd = nIEZPWjUtyawwcldVOhxs[0];for(seCKelpafkh" ascii
    $s18 = "function gobrsGWF(){return nAhqZYoLrNjZxd.ExpandEnvironmentStrings(TlQSDyp())}" fullword ascii
    $s19 = "function rjpXOiyP(wkeAzxyaJfogUPmGddj,mIjOZti){return String.fromCharCode(wkeAzxyaJfogUPmGddj,mIjOZti);}" fullword ascii
    $s20 = "function tLPPBRAU(aFGMvXDwfNtnez,GvKcZj) {var BJtRJIwWH=[nIEZPWjUtyawwcldVOhxs[15]];aFGMvXDwfNtnez[BJtRJIwWH[0]]" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}