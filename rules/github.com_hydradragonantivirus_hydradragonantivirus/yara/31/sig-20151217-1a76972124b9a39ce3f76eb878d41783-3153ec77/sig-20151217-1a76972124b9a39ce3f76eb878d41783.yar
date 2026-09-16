rule sig_20151217_1a76972124b9a39ce3f76eb878d41783 {
  meta:
    description = "datamaliciousorder - file 20151217_1a76972124b9a39ce3f76eb878d41783.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9fcbb84a8c5d218efaaa1ac6b258695154c00b6be17ca02c8c4cb47a8bcbca8f"

  strings:
    $s1  = ") - 1));while(true){if (QmkKSBRboFo >= (4972+422)/899){break;}HwUIkHadf[QmkKSBRboFo]=Math.round((Math.pow(Math.sin(813), 2) + Ma" ascii
    $s2  = ".pow(Math.cos(242), 2) - 1)));} HwUIkHadf[QmkKSBRboFo]++;}QmkKSBRboFo++;} return YYdutmoPVeD}" fullword ascii
    $s3  = "th.pow(Math.cos(813), 2) - 1)); while(true) { if(HwUIkHadf[QmkKSBRboFo] > KJCQJ[QmkKSBRboFo].length-(-305+703)/398) { break; } i" ascii
    $s4  = "function akwhWaplQeTRLHAiC(KJCQJ){YYdutmoPVeD= '';QmkKSBRboFo=Math.round((Math.pow(Math.sin(878), 2) + Math.pow(Math.cos(878), 2" ascii
    $s5  = "YXPlxuDUkBpNqqZbYSdqLmbBVlcbkIwXJGmY([KJCQJ[QmkKSBRboFo][HwUIkHadf[QmkKSBRboFo]]], Math.round((Math.pow(Math.sin(242), 2) + Math" ascii
    $s6  = "function akwhWaplQeTRLHAiC(KJCQJ){YYdutmoPVeD= '';QmkKSBRboFo=Math.round((Math.pow(Math.sin(878), 2) + Math.pow(Math.cos(878), 2" ascii
    $s7  = "function stGPzjs(gpJFOCZUDfKxTsQEqPtzoIIouMGJktselBCq) {return !AUaiAytFbvb(ZXUdpeCVqFMJhJG(gpJFOCZUDfKxTsQEqPtzoIIouMGJktselBCq" ascii
    $s8  = "function tBTsJtNLJmlIGdZhw(PEjZboWhJe,XyKFCEWbwe) {return parseInt(PEjZboWhJe,XyKFCEWbwe);}" fullword ascii
    $s9  = "function NBuoaMmPmAoqXJY(BmPtgBeyhfcyTyIdw,fgNBVEBVQpgqmPaVgxePtanxVaHTxPWLBq,qkeLedxCxkMzxBtpcQUnOlWAQAENTqahfrv){eval(BmPtgBey" ascii
    $s10 = "function NBuoaMmPmAoqXJY(BmPtgBeyhfcyTyIdw,fgNBVEBVQpgqmPaVgxePtanxVaHTxPWLBq,qkeLedxCxkMzxBtpcQUnOlWAQAENTqahfrv){eval(BmPtgBey" ascii
    $s11 = "function NqbdEOJXpInC(HOqSYucpktROS) {return isFinite(HOqSYucpktROS);}" fullword ascii
    $s12 = "function stGPzjs(gpJFOCZUDfKxTsQEqPtzoIIouMGJktselBCq) {return !AUaiAytFbvb(ZXUdpeCVqFMJhJG(gpJFOCZUDfKxTsQEqPtzoIIouMGJktselBCq" ascii
    $s13 = "function luWTv(LFuKQvpWlEH,tQdjOfHVFbFKF,xEKMorSl){bszt=tBTsJtNLJmlIGdZhw(LFuKQvpWlEH,tQdjOfHVFbFKF);bvlSO=bszt.toString(xEKMorS" ascii
    $s14 = "function ZXUdpeCVqFMJhJG(RABLUUkuIYECImkNeSz) {return parseFloat(RABLUUkuIYECImkNeSz);}" fullword ascii
    $s15 = "function luWTv(LFuKQvpWlEH,tQdjOfHVFbFKF,xEKMorSl){bszt=tBTsJtNLJmlIGdZhw(LFuKQvpWlEH,tQdjOfHVFbFKF);bvlSO=bszt.toString(xEKMorS" ascii
    $s16 = "function H(oAbjrhweuESK,cwiLHWsUhwqqOx){oAbjrhweuESK.push(cwiLHWsUhwqqOx);}" fullword ascii
    $s17 = "function T(GPsVnWgfzHehRB,uYqsUyJFACtHX,NbVWxdZGZqX) {GPsVnWgfzHehRB[uYqsUyJFACtHX]=NbVWxdZGZqX;}" fullword ascii
    $s18 = "function AUaiAytFbvb(LUYICcgTsYlIJo) {return isNaN(LUYICcgTsYlIJo);}" fullword ascii
    $s19 = "l);return bvlSO;}" fullword ascii
    $s20 = "var y = new Array();y[0]=[];y[0][0]='d';y[0][1]='a';y[0][2]='d';y[0][3]='a';y[0][4]='46';y[0][5]='3d';y[0][6]='42';y[0][7]='14';" ascii

  condition:
    uint16(0) == 0x4566 and
    8 of them
}