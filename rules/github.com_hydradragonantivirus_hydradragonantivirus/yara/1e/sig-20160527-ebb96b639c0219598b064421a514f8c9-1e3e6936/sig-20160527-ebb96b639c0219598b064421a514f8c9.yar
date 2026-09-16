rule sig_20160527_ebb96b639c0219598b064421a514f8c9 {
  meta:
    description = "datamaliciousorder - file 20160527_ebb96b639c0219598b064421a514f8c9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78b6e6aaa8e5abf66a7bffe57d395ef858d394b640ef4c3f5bdcec6c7bee710c"

  strings:
    $s1  = "function IPVaxOsHInQQiS() {return WScript;}function eMmnJhNmq(){return ltZPXDstnF.ExpandEnvironmentStrings(rOtFqFvXfkec())}" fullword ascii
    $s2  = "function yBuxJrOxRLzBv(YXwXcmx,lQniKgjtFmAVp){return YXwXcmx.charAt(lQniKgjtFmAVp);}" fullword ascii
    $s3  = "function rOtFqFvXfkec(){return znrYSTwMssvz(vuiQvWBfamXLQSpEOleAm[8],[1,5,7],vuiQvWBfamXLQSpEOleAm[9]);}" fullword ascii
    $s4  = "function ZIVlhJKSQrjSxgtTgOQm(tTtJdBWSlaHOGfaqqZ,KKJtDGhHyYFbQAPw,VBZVSDzJkBPEQvM){return String.fromCharCode(tTtJdBWSlaHOGfaqqZ" ascii
    $s5  = "function cD(EFoBnzv){return String.fromCharCode(EFoBnzv);}" fullword ascii
    $s6  = "function uaKQEyfi(){return znrYSTwMssvz(vuiQvWBfamXLQSpEOleAm[10],[2,4,8,10],vuiQvWBfamXLQSpEOleAm[11]);}" fullword ascii
    $s7  = "sMrUZ == 64) CIPAryTcRznFRwxRMc += cD(wSXDJosLPGFZmJQuf);else if (PDgDPrhQxglYAKMwtwa == 64) CIPAryTcRznFRwxRMc += VRidLM(wSXDJo" ascii
    $s8  = "function ZIVlhJKSQrjSxgtTgOQm(tTtJdBWSlaHOGfaqqZ,KKJtDGhHyYFbQAPw,VBZVSDzJkBPEQvM){return String.fromCharCode(tTtJdBWSlaHOGfaqqZ" ascii
    $s9  = "sLPGFZmJQuf, nwERjZTHCpiCqHeUnN);else CIPAryTcRznFRwxRMc += ZIVlhJKSQrjSxgtTgOQm(wSXDJosLPGFZmJQuf, nwERjZTHCpiCqHeUnN, rSalFAIY" ascii
    $s10 = "4];for(TrHAakVK=0;TrHAakVK<iyGrdAHzUhbzo.length;TrHAakVK++) {CQtePjYocC+=KnBXPnWRkcm[iyGrdAHzUhbzo[TrHAakVK]];}return CQtePjYocC" ascii
    $s11 = "function znrYSTwMssvz(lFYxZtmEwl,iyGrdAHzUhbzo,gFMLqT){KnBXPnWRkcm=lFYxZtmEwl.split(gFMLqT);CQtePjYocC = vuiQvWBfamXLQSpEOleAm[1" ascii
    $s12 = "function DXJlLiSCzefQ(mDpFyAYV,RzPrw) {var BaDBuiUQCQOUP=[vuiQvWBfamXLQSpEOleAm[15]];mDpFyAYV[BaDBuiUQCQOUP[0]](RzPrw,0x1,0x0)}" fullword ascii
    $s13 = "function MMvAzBCmVBjyMN(XIwyYxEIJMkuz) {var GUGcnBoaNRWs = ahSxraUVyro.join(vuiQvWBfamXLQSpEOleAm[6]);var wSXDJosLPGFZmJQuf, nwE" ascii
    $s14 = "function VRidLM(qDTqGrDobOJNG,rZpFnCdOSPRseaOyeGCMpUBZ){return String.fromCharCode(qDTqGrDobOJNG,rZpFnCdOSPRseaOyeGCMpUBZ);}" fullword ascii
    $s15 = "ng.fromCharCode(92)+vuiQvWBfamXLQSpEOleAm[4],true);" fullword ascii
    $s16 = "e);} while (LctKgXvsqqeXfFZXtLDBvA < XIwyYxEIJMkuz.length);return CIPAryTcRznFRwxRMc;}" fullword ascii
    $s17 = "function BqEYLUaoiJErjeFl(XqmaJlykWMdQi,VLOkgIuHjHBhzr){return XqmaJlykWMdQi.indexOf(VLOkgIuHjHBhzr);}" fullword ascii
    $s18 = "var PyuMr=function(){return new ActiveXObject(vuiQvWBfamXLQSpEOleAm[0]);}();" fullword ascii
    $s19 = "var ltZPXDstnF=function(){return IPVaxOsHInQQiS().CreateObject(vuiQvWBfamXLQSpEOleAm[1].replace(new RegExp(\"u\",\"g\"),\"\"));}" ascii
    $s20 = "function znrYSTwMssvz(lFYxZtmEwl,iyGrdAHzUhbzo,gFMLqT){KnBXPnWRkcm=lFYxZtmEwl.split(gFMLqT);CQtePjYocC = vuiQvWBfamXLQSpEOleAm[1" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}