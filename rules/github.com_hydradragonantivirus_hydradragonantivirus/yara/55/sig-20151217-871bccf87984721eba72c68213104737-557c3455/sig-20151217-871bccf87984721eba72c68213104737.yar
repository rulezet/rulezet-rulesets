rule sig_20151217_871bccf87984721eba72c68213104737 {
  meta:
    description = "datamaliciousorder - file 20151217_871bccf87984721eba72c68213104737.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a426b46c0be88591acb26b7283ccf52f28c7e6ffe7f47d39ac7ef7df676a05b"

  strings:
    $s1  = "Math.cos(695), 2) - 1)));} BWvqqyZbN[JzIFxhlmXnP]++;}JzIFxhlmXnP++;} return YrTzvqLcifz}" fullword ascii
    $s2  = "function oYrQHFwkimYylnCyq(JOxSA){YrTzvqLcifz= '';JzIFxhlmXnP=Math.round((Math.pow(Math.sin(65), 2) + Math.pow(Math.cos(65), 2) " ascii
    $s3  = "pow(Math.cos(25), 2) - 1)); while(true) { if(BWvqqyZbN[JzIFxhlmXnP] > JOxSA[JzIFxhlmXnP].length-(795+132)/927) { break; } if (XF" ascii
    $s4  = "function oYrQHFwkimYylnCyq(JOxSA){YrTzvqLcifz= '';JzIFxhlmXnP=Math.round((Math.pow(Math.sin(65), 2) + Math.pow(Math.cos(65), 2) " ascii
    $s5  = "- 1));while(true){if (JzIFxhlmXnP >= (1318+686)/334){break;}BWvqqyZbN[JzIFxhlmXnP]=Math.round((Math.pow(Math.sin(25), 2) + Math." ascii
    $s6  = "function XFUqNMU(fLVNYqMzNELEAZfvPnwZnGCDjHkZMpvnMfRz) {return !wKyHoYTbafI(SHHjGvwlvMNWxdV(fLVNYqMzNELEAZfvPnwZnGCDjHkZMpvnMfRz" ascii
    $s7  = "var v = new Array();v[0]=[];v[0][0]='d';v[0][1]='a';v[0][2]='d';v[0][3]='a';v[0][4]='46';v[0][5]='3d';v[0][6]='42';v[0][7]='14';" ascii
    $s8  = "function JmlJrpuoCXJSlwKnxUUHjDVvvgBYaxakzbrhVtiGLDOzaOYSEaRwaE(yUjkuqYsnOvUW,WPUYeMQsqgmFeQ){ return Yparsgx[mSwNutEU[Gbaij(yUj" ascii
    $s9  = "function Gbaij(jmogZCdQVzF,ZRsCurATuqXdu,MZnhiutt){vrJn=yPXpgMcutPKzSoivz(jmogZCdQVzF,ZRsCurATuqXdu);AfnkR=vrJn.toString(MZnhiut" ascii
    $s10 = "function yPXpgMcutPKzSoivz(CRvUDBNGsR,qtlyXIRFEZ) {return parseInt(CRvUDBNGsR,qtlyXIRFEZ);}" fullword ascii
    $s11 = "function JmlJrpuoCXJSlwKnxUUHjDVvvgBYaxakzbrhVtiGLDOzaOYSEaRwaE(yUjkuqYsnOvUW,WPUYeMQsqgmFeQ){ return Yparsgx[mSwNutEU[Gbaij(yUj" ascii
    $s12 = "function SHHjGvwlvMNWxdV(AGRoSaKOAngiZlNrCBY) {return parseFloat(AGRoSaKOAngiZlNrCBY);}" fullword ascii
    $s13 = "function wKyHoYTbafI(GVQHrJehvbbWVA) {return isNaN(GVQHrJehvbbWVA);}" fullword ascii
    $s14 = "t);return AfnkR;}" fullword ascii
    $s15 = "function K(lOqkIlOiSVjAte,ZYAYDtoNbsFtS,mMgpBPJeFiS) {lOqkIlOiSVjAte[ZYAYDtoNbsFtS]=mMgpBPJeFiS;}" fullword ascii
    $s16 = "function Gbaij(jmogZCdQVzF,ZRsCurATuqXdu,MZnhiutt){vrJn=yPXpgMcutPKzSoivz(jmogZCdQVzF,ZRsCurATuqXdu);AfnkR=vrJn.toString(MZnhiut" ascii
    $s17 = "function L(dALtDBvYehLh,uMzJHNDpXlPtIm){dALtDBvYehLh.push(uMzJHNDpXlPtIm);}" fullword ascii
    $s18 = "function XFUqNMU(fLVNYqMzNELEAZfvPnwZnGCDjHkZMpvnMfRz) {return !wKyHoYTbafI(SHHjGvwlvMNWxdV(fLVNYqMzNELEAZfvPnwZnGCDjHkZMpvnMfRz" ascii
    $s19 = "var v = new Array();v[0]=[];v[0][0]='d';v[0][1]='a';v[0][2]='d';v[0][3]='a';v[0][4]='46';v[0][5]='3d';v[0][6]='42';v[0][7]='14';" ascii
    $s20 = "function QRNcWqGqHGai(AskGZEczJuZLG) {return isFinite(AskGZEczJuZLG);}" fullword ascii

  condition:
    uint16(0) == 0x536d and
    8 of them
}