rule sig_20160531_d3a0cc82dc6a9ab87602735eb302315e {
  meta:
    description = "datamaliciousorder - file 20160531_d3a0cc82dc6a9ab87602735eb302315e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f87dab246d19bd3b5de33a91c82122c9c4fb6a7e0a32921d8fbde9960deaa3c4"

  strings:
    $s1  = "var jkobmYMUsj=function(){return WScript.CreateObject(SPrPwqPqNmXrYK[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function zNnMLfye(rOqTRduCNVFLpyLKWGBLQDJ,nQrEsl){return rOqTRduCNVFLpyLKWGBLQDJ.charAt(nQrEsl);}" fullword ascii
    $s3  = "function gbbmgurKNf(HpeuauFKXHtbz,oxopfwOIhvvr,AEtrNY){CKEBJuZkeHSm=HpeuauFKXHtbz.split(AEtrNY);FuZaBRO = SPrPwqPqNmXrYK[0];for(" ascii
    $s4  = "function ntTasXbLpyyTPNuvSjr(GGegnnVRjQ,SujboGjt){return GGegnnVRjQ.indexOf(SujboGjt);}" fullword ascii
    $s5  = "var Vkiqu=function(){return new ActiveXObject(SPrPwqPqNmXrYK[1]);}();" fullword ascii
    $s6  = "function NBQjQlJw(dPdBnByALDiee) {var iPjEdNXdTKgnInGJiJKUtDDH = SrogUGYOH.join(SPrPwqPqNmXrYK[7]);var KhJaAAjV, mfUjwTzxj, OPFi" ascii
    $s7  = "function gbbmgurKNf(HpeuauFKXHtbz,oxopfwOIhvvr,AEtrNY){CKEBJuZkeHSm=HpeuauFKXHtbz.split(AEtrNY);FuZaBRO = SPrPwqPqNmXrYK[0];for(" ascii
    $s8  = "tygvfGlgme(KhJaAAjV, mfUjwTzxj, OPFiiSRMAVNGtButNXHz);} while (qevlYMmmwdlZexl < dPdBnByALDiee.length);return TplPOyZsvefakncuKA" ascii
    $s9  = "function QDEKHab(){return gbbmgurKNf(SPrPwqPqNmXrYK[13],[0,3,6],SPrPwqPqNmXrYK[14]);}" fullword ascii
    $s10 = "function qdXlWYwuHQtygvfGlgme(OSUFPOMEbqag,miRDIQqFzdhdFDgrVDo,XKXSepDJJSbiJRXAyoPG){return String.fromCharCode(OSUFPOMEbqag,miR" ascii
    $s11 = "function Pj(trETRqL){return String.fromCharCode(trETRqL);}" fullword ascii
    $s12 = "function NBQjQlJw(dPdBnByALDiee) {var iPjEdNXdTKgnInGJiJKUtDDH = SrogUGYOH.join(SPrPwqPqNmXrYK[7]);var KhJaAAjV, mfUjwTzxj, OPFi" ascii
    $s13 = "ff;OPFiiSRMAVNGtButNXHz = fqLmfRySxFqNT & 0xff;if (pldXpjvsSzeemMtZ == 64) TplPOyZsvefakncuKAJEFDkp += Pj(KhJaAAjV);else if (Mcm" ascii
    $s14 = "function KkGuRPFSXxuCb(){return gbbmgurKNf(SPrPwqPqNmXrYK[11],[2,4,8,10],SPrPwqPqNmXrYK[12]);}" fullword ascii
    $s15 = "SASVV=0;SASVV<oxopfwOIhvvr.length;SASVV++) {FuZaBRO+=CKEBJuZkeHSm[oxopfwOIhvvr[SASVV]];}return FuZaBRO.substring(3,FuZaBRO.lengt" ascii
    $s16 = "VhBeGkfvjnzQ == 64) TplPOyZsvefakncuKAJEFDkp += TmRHvGLWeUOviOu(KhJaAAjV, mfUjwTzxj);else TplPOyZsvefakncuKAJEFDkp += qdXlWYwuHQ" ascii
    $s17 = "function uxpJegnm(){return jkobmYMUsj.ExpandEnvironmentStrings(YVQdgN())}" fullword ascii
    $s18 = "function TmRHvGLWeUOviOu(zAjofruJsO,auaWiPWhaGUcmnyqMvSMvoF){return String.fromCharCode(zAjofruJsO,auaWiPWhaGUcmnyqMvSMvoF);}" fullword ascii
    $s19 = "function YVQdgN(){return gbbmgurKNf(SPrPwqPqNmXrYK[9],[1,5,7],SPrPwqPqNmXrYK[10]);}" fullword ascii
    $s20 = "function qdXlWYwuHQtygvfGlgme(OSUFPOMEbqag,miRDIQqFzdhdFDgrVDo,XKXSepDJJSbiJRXAyoPG){return String.fromCharCode(OSUFPOMEbqag,miR" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}