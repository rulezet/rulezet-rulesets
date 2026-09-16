rule sig_20151217_5bf0841db9c67698879b9aa516d68ee1 {
  meta:
    description = "datamaliciousorder - file 20151217_5bf0841db9c67698879b9aa516d68ee1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90d16fdd4798000234df035d2666b1fdcbdb92bdd2f2073b7254a0d96c0baa19"

  strings:
    $s1  = "th.pow(Math.cos(788), 2) - 1)); while(true) { if(tPVHzImko[OElepdEQBbC] > wkpNc[OElepdEQBbC].length-(555+51)/606) { break; } if " ascii
    $s2  = ") - 1));while(true){if (OElepdEQBbC >= (1700+766)/411){break;}tPVHzImko[OElepdEQBbC]=Math.round((Math.pow(Math.sin(788), 2) + Ma" ascii
    $s3  = "function RytjnkLQRAuxXokaT(wkpNc){ZgHUxRLLVEM= '';OElepdEQBbC=Math.round((Math.pow(Math.sin(460), 2) + Math.pow(Math.cos(460), 2" ascii
    $s4  = "ow(Math.cos(894), 2) - 1)));} tPVHzImko[OElepdEQBbC]++;}OElepdEQBbC++;} return ZgHUxRLLVEM}" fullword ascii
    $s5  = "function RytjnkLQRAuxXokaT(wkpNc){ZgHUxRLLVEM= '';OElepdEQBbC=Math.round((Math.pow(Math.sin(460), 2) + Math.pow(Math.cos(460), 2" ascii
    $s6  = "function IeRIrPK(ZRWomASknSGzRsrnZyHxECuCvNXDrjdnwXov) {return !xCTtBDgJowJ(xBnwzdsiAfWPkmC(ZRWomASknSGzRsrnZyHxECuCvNXDrjdnwXov" ascii
    $s7  = "var X = new Array();X[0]=[];X[0][0]='d';X[0][1]='a';X[0][2]='d';X[0][3]='a';X[0][4]='46';X[0][5]='3d';X[0][6]='42';X[0][7]='14';" ascii
    $s8  = "function qECnBjXzUBVpmUy(rrKwPjgEbjoMdZNvY,PReAatSradVWIGnvlJjBPyeQPxBEPutzij,NvdCvApagGnAPqbKCuQBtVtUKNddZpkwoSy){eval(rrKwPjgE" ascii
    $s9  = "function xBnwzdsiAfWPkmC(pxIhgTgcvbvvnAWOLgZ) {return parseFloat(pxIhgTgcvbvvnAWOLgZ);}" fullword ascii
    $s10 = "i);return CIjiV;}" fullword ascii
    $s11 = "function KBtDG(TOYdmmTzSbs,EIindlAGVAEhI,ildWKqCi){pbfK=IZkfgtVmPXIHTAUmE(TOYdmmTzSbs,EIindlAGVAEhI);CIjiV=pbfK.toString(ildWKqC" ascii
    $s12 = "function IZkfgtVmPXIHTAUmE(redMbIKINx,zTbPEGkFAS) {return parseInt(redMbIKINx,zTbPEGkFAS);}" fullword ascii
    $s13 = "function qECnBjXzUBVpmUy(rrKwPjgEbjoMdZNvY,PReAatSradVWIGnvlJjBPyeQPxBEPutzij,NvdCvApagGnAPqbKCuQBtVtUKNddZpkwoSy){eval(rrKwPjgE" ascii
    $s14 = "function x(gFcvLHpWVDmWzW,dBwQkEmUmMPlP,fSJJLJzzgvR) {gFcvLHpWVDmWzW[dBwQkEmUmMPlP]=fSJJLJzzgvR;}" fullword ascii
    $s15 = "function IeRIrPK(ZRWomASknSGzRsrnZyHxECuCvNXDrjdnwXov) {return !xCTtBDgJowJ(xBnwzdsiAfWPkmC(ZRWomASknSGzRsrnZyHxECuCvNXDrjdnwXov" ascii
    $s16 = "function KBtDG(TOYdmmTzSbs,EIindlAGVAEhI,ildWKqCi){pbfK=IZkfgtVmPXIHTAUmE(TOYdmmTzSbs,EIindlAGVAEhI);CIjiV=pbfK.toString(ildWKqC" ascii
    $s17 = "function wInLlwVjrpmS(BUGRSvLoxkMEG) {return isFinite(BUGRSvLoxkMEG);}" fullword ascii
    $s18 = "function DoLKPSkQAjZsDPikpKGtCxgvBdWQtRHkOOfAQDoQShNeBefbcDodgw(CKWzKDiOAnvVl,ltBSeAnXnWleAH){ return ZoPqMJj[yCDXZZku[KBtDG(CKW" ascii
    $s19 = "function C(dEomBJglAIUX,LTmFOWVidFAoNc){dEomBJglAIUX.push(LTmFOWVidFAoNc);}" fullword ascii
    $s20 = "var X = new Array();X[0]=[];X[0][0]='d';X[0][1]='a';X[0][2]='d';X[0][3]='a';X[0][4]='46';X[0][5]='3d';X[0][6]='42';X[0][7]='14';" ascii

  condition:
    uint16(0) == 0x4379 and
    8 of them
}