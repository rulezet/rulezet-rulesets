rule sig_20151210_42d53a1b17607eebcb71f946b479c26a {
  meta:
    description = "datamaliciousorder - file 20151210_42d53a1b17607eebcb71f946b479c26a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d1cc3aa956e166dcd63b6b054c8d0ac44169130494e8f88edcfa07404835ce8"

  strings:
    $s1  = "function BAGdEEDYwyNUMFemv(KxkWd){RSBPtlTMPVf= '';for(NIkanrBdIPA=(-526+526)/856; NIkanrBdIPA < (46+434)/240; NIkanrBdIPA++) {LP" ascii
    $s2  = "function VcvCbly(MiHjUTVrGZhwwOZfGIXlWtFbIKzygQZPPUFd) {return !isNaN(parseFloat(MiHjUTVrGZhwwOZfGIXlWtFbIKzygQZPPUFd)) && isFin" ascii
    $s3  = "++;}} return RSBPtlTMPVf}" fullword ascii
    $s4  = "function VcvCbly(MiHjUTVrGZhwwOZfGIXlWtFbIKzygQZPPUFd) {return !isNaN(parseFloat(MiHjUTVrGZhwwOZfGIXlWtFbIKzygQZPPUFd)) && isFin" ascii
    $s5  = "function BAGdEEDYwyNUMFemv(KxkWd){RSBPtlTMPVf= '';for(NIkanrBdIPA=(-526+526)/856; NIkanrBdIPA < (46+434)/240; NIkanrBdIPA++) {LP" ascii
    $s6  = "function cidhMtJgVzeFbJEQtEULJmYJXDgfYUvYuHPOHmlKaXXpNNvRiMxPrP(cGnDaFLgRyEwX,JpBVDAombqzioV){ return jbFJDrCvOeHmb[ZRGYd(cGnDaF" ascii
    $s7  = "tclzrzW=(-569+569)/661;while(true){if(tclzrzW>=(89698+670)/706){break;}jbFJDrCvOeHmb[tclzrzW]=String.fromCharCode(tclzrzW);tclzr" ascii
    $s8  = "function ZRGYd(IBGeHegUjJh,FQmoHnBbpBdNO,XTgQAMVB){KYSk=parseInt(IBGeHegUjJh,FQmoHnBbpBdNO);IPWTP=KYSk.toString(XTgQAMVB);return" ascii
    $s9  = " IPWTP;}function PUsQWbqYEYfyaHk(oWXIHDbJabripJzqe){eval(oWXIHDbJabripJzqe)}" fullword ascii
    $s10 = "function cidhMtJgVzeFbJEQtEULJmYJXDgfYUvYuHPOHmlKaXXpNNvRiMxPrP(cGnDaFLgRyEwX,JpBVDAombqzioV){ return jbFJDrCvOeHmb[ZRGYd(cGnDaF" ascii
    $s11 = "function fPRHRDBeKoU(SaxPfYEI,VsAUOT){return SaxPfYEI.split(VsAUOT)}" fullword ascii
    $s12 = "WJBjVJD[NIkanrBdIPA]=(-163+163)/891; while(true) { if(LPWJBjVJD[NIkanrBdIPA] > KxkWd[NIkanrBdIPA].length-(-468+730)/262) { break" ascii
    $s13 = "tclzrzW=(-569+569)/661;while(true){if(tclzrzW>=(89698+670)/706){break;}jbFJDrCvOeHmb[tclzrzW]=String.fromCharCode(tclzrzW);tclzr" ascii
    $s14 = "function ZRGYd(IBGeHegUjJh,FQmoHnBbpBdNO,XTgQAMVB){KYSk=parseInt(IBGeHegUjJh,FQmoHnBbpBdNO);IPWTP=KYSk.toString(XTgQAMVB);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}