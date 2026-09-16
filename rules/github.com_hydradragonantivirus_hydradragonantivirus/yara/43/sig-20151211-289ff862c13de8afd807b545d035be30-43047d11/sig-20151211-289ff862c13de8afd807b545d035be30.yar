rule sig_20151211_289ff862c13de8afd807b545d035be30 {
  meta:
    description = "datamaliciousorder - file 20151211_289ff862c13de8afd807b545d035be30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9a123cde9fbafa21352220912d26259f73d3f7ade270e9f6d87d4cb197ea397"

  strings:
    $s1  = "function wZwDrUQ(kzFUMlGEVlTlGaxOCMRgoficVFORRzOnYEnr) {return !isNaN(parseFloat(kzFUMlGEVlTlGaxOCMRgoficVFORRzOnYEnr)) && isFin" ascii
    $s2  = "function wZwDrUQ(kzFUMlGEVlTlGaxOCMRgoficVFORRzOnYEnr) {return !isNaN(parseFloat(kzFUMlGEVlTlGaxOCMRgoficVFORRzOnYEnr)) && isFin" ascii
    $s3  = "function clUPv(uGdXBlqGApy,zAEYpyVEGafYp,ulfNYnss){vaQq=parseInt(uGdXBlqGApy,zAEYpyVEGafYp);Xlqoa=vaQq.toString(ulfNYnss);return" ascii
    $s4  = "var U=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"42\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii
    $s5  = "function wqjXfPXyYtWOrRyzm(SFZtM){YPqwlkjTxvq= '';IXqFIGQtdTS=(-766+766)/442; while(true){if(IXqFIGQtdTS >= (817+267)/542)break;" ascii
    $s6  = "XVmlvcbIl[IXqFIGQtdTS]=(-583+583)/573; while(true) { if(XVmlvcbIl[IXqFIGQtdTS] > SFZtM[IXqFIGQtdTS].length-(-399+432)/33) { brea" ascii
    $s7  = " Xlqoa;}function iRdmlVJSixJQYYs(AITOgLkEPgdgKODzy){eval(AITOgLkEPgdgKODzy)}" fullword ascii
    $s8  = "function lJhfWCvPbmIInvQfteLcWHVARaTVbAILSNYSyXmaiRKTeFlTpqtIUy(uHVxEMhzxtrAI,lkkrMsXmwQjUxr){ return bqojt[clUPv(uHVxEMhzxtrAI[" ascii
    $s9  = "var e=new Array(\"2f\",\"2a\",\"28\",\"2b\",\"2d\",\"2d\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s10 = "function clUPv(uGdXBlqGApy,zAEYpyVEGafYp,ulfNYnss){vaQq=parseInt(uGdXBlqGApy,zAEYpyVEGafYp);Xlqoa=vaQq.toString(ulfNYnss);return" ascii
    $s11 = "function lJhfWCvPbmIInvQfteLcWHVARaTVbAILSNYSyXmaiRKTeFlTpqtIUy(uHVxEMhzxtrAI,lkkrMsXmwQjUxr){ return bqojt[clUPv(uHVxEMhzxtrAI[" ascii
    $s12 = "var e=new Array(\"2f\",\"2a\",\"28\",\"2b\",\"2d\",\"2d\",\"2h\",\"d\",\"a\",\"4i\",\"56\",\"59\",\"1b\",\"1j\",\"5d\",\"4d\",\"" ascii
    $s13 = "function VvhvNhUgJYM(LAbHqDWF,JwZhQr){return LAbHqDWF.split(JwZhQr)}" fullword ascii
    $s14 = "+;}IXqFIGQtdTS++;} return YPqwlkjTxvq}" fullword ascii
    $s15 = "function wqjXfPXyYtWOrRyzm(SFZtM){YPqwlkjTxvq= '';IXqFIGQtdTS=(-766+766)/442; while(true){if(IXqFIGQtdTS >= (817+267)/542)break;" ascii
    $s16 = "var U=new Array(\"d\",\"a\",\"d\",\"a\",\"5d\",\"4d\",\"59\",\"1b\",\"42\",\"1b\",\"2j\",\"1b\",\"1d\",\"5a\",\"56\",\"4i\",\"5b" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}