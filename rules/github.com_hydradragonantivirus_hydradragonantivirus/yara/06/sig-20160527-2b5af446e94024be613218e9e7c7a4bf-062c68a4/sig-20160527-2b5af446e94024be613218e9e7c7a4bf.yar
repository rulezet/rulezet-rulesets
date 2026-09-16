rule sig_20160527_2b5af446e94024be613218e9e7c7a4bf {
  meta:
    description = "datamaliciousorder - file 20160527_2b5af446e94024be613218e9e7c7a4bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac694e830a7130f71777f3bae9d20c5a94c46efbf74f2566803a9dbd0a4d6af7"

  strings:
    $s1  = "function uqdNcMAVFMKmyyVSJfx(LIlvYGxOHbcpjJfOPZPof,qQnhCZEEgJsOd){return LIlvYGxOHbcpjJfOPZPof.charAt(qQnhCZEEgJsOd);}" fullword ascii
    $s2  = "pjWMgBCOIDlI.length);return mBjfBxhLWvOVOmnluJtGyecQ;}" fullword ascii
    $s3  = "function joAMCa() {return WScript;}function lTJFNoBrwmxim(){return gwyJMqAKFXcIJZ.ExpandEnvironmentStrings(RXaHSzHzdlx())}" fullword ascii
    $s4  = "var GGvWlvxgq = fhtaymjoSHBOT.createtextfile(gwyJMqAKFXcIJZ.ExpandEnvironmentStrings(CzVyBOgLMp[2]+CzVyBOgLMp[3])+String.fromCha" ascii
    $s5  = "function KsDdV(diuHlniQjLs,zvPtpB,nlBsTyKed){saruQVbg=diuHlniQjLs.split(nlBsTyKed);XoctEvReYcdKyn = CzVyBOgLMp[14];for(bemShmz=0" ascii
    $s6  = "var fhtaymjoSHBOT=function(){return new ActiveXObject(CzVyBOgLMp[0]);}();" fullword ascii
    $s7  = ";bemShmz<zvPtpB.length;bemShmz++) {XoctEvReYcdKyn+=saruQVbg[zvPtpB[bemShmz]];}return XoctEvReYcdKyn.substring(3,XoctEvReYcdKyn.l" ascii
    $s8  = "rCode(92)+CzVyBOgLMp[4],true);" fullword ascii
    $s9  = "function bsciGabGPwC(eGPovPsSN,AtJVDsGKRGxOIoExFcKfI,zdqtZRMNeHF){return String.fromCharCode(eGPovPsSN,AtJVDsGKRGxOIoExFcKfI,zdq" ascii
    $s10 = "function yeSlIFiiPVR(AjEuSBIYtYqHU,SWUWxGH){return AjEuSBIYtYqHU.indexOf(SWUWxGH);}" fullword ascii
    $s11 = "function DC(QjkygzmMdxlxdaMaF){return String.fromCharCode(QjkygzmMdxlxdaMaF);}" fullword ascii
    $s12 = "xmMQMVbqJaDn == 64) mBjfBxhLWvOVOmnluJtGyecQ += sjfypBUDmBnbzvXLhmnGGHk(ZnuRLiktybAAoNBCUJQOj, DeRHbMNXNRxnKWxqF);else mBjfBxhLW" ascii
    $s13 = "function HOBmL(jpjWMgBCOIDlI) {var gaELMxFFFVgNJJsW = bVdsSiKOuUklhAXrlW.join(CzVyBOgLMp[6]);var ZnuRLiktybAAoNBCUJQOj, DeRHbMNX" ascii
    $s14 = "push(\"D\");bVdsSiKOuUklhAXrlW.push(\"3\");bVdsSiKOuUklhAXrlW.push(\"E\");bVdsSiKOuUklhAXrlW.push(\"F\");bVdsSiKOuUklhAXrlW.push" ascii
    $s15 = "function HOBmL(jpjWMgBCOIDlI) {var gaELMxFFFVgNJJsW = bVdsSiKOuUklhAXrlW.join(CzVyBOgLMp[6]);var ZnuRLiktybAAoNBCUJQOj, DeRHbMNX" ascii
    $s16 = "function zyttMQQBo(){return KsDdV(CzVyBOgLMp[12],[0,3,6],CzVyBOgLMp[13]);}" fullword ascii
    $s17 = "function bsciGabGPwC(eGPovPsSN,AtJVDsGKRGxOIoExFcKfI,zdqtZRMNeHF){return String.fromCharCode(eGPovPsSN,AtJVDsGKRGxOIoExFcKfI,zdq" ascii
    $s18 = "function ShyWVzhjDBmCfu(){return KsDdV(CzVyBOgLMp[10],[2,4,8,10],CzVyBOgLMp[11]);}" fullword ascii
    $s19 = "function KsDdV(diuHlniQjLs,zvPtpB,nlBsTyKed){saruQVbg=diuHlniQjLs.split(nlBsTyKed);XoctEvReYcdKyn = CzVyBOgLMp[14];for(bemShmz=0" ascii
    $s20 = "function sjfypBUDmBnbzvXLhmnGGHk(EtsRHnnvJmRddWasL,ZYtGVk){return String.fromCharCode(EtsRHnnvJmRddWasL,ZYtGVk);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}