rule sig_20160530_5ee902aece3b3dd5a126319c1507a7a1 {
  meta:
    description = "datamaliciousorder - file 20160530_5ee902aece3b3dd5a126319c1507a7a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c343f05ae2c4f907e5b8130eb25b395f77ac4acfdcb197733783da07ee1ea0af"

  strings:
    $s1  = "var qybIUF=function(){return WScript.CreateObject(TPazCkMiYuc[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "UpGlI.length);return lnoywzzNIrBjIPZNjkZ;}" fullword ascii
    $s3  = "push(\"t\");BtsyvfXcHkUanO.push(\"u\");BtsyvfXcHkUanO.push(\"v\");BtsyvfXcHkUanO.push(\"w\");BtsyvfXcHkUanO.push(\"x\");BtsyvfXc" ascii
    $s4  = "function lbZVUMokZzSSBtqagI(MdqQOLoZIsQJcaFUSTLNiAKo,YsXaLQMmwOdsiJcPdGTnY){return MdqQOLoZIsQJcaFUSTLNiAKo.charAt(YsXaLQMmwOdsi" ascii
    $s5  = "function lbZVUMokZzSSBtqagI(MdqQOLoZIsQJcaFUSTLNiAKo,YsXaLQMmwOdsiJcPdGTnY){return MdqQOLoZIsQJcaFUSTLNiAKo.charAt(YsXaLQMmwOdsi" ascii
    $s6  = "function RotlExxNbmO(CSJlqJrFUpGlI) {var FSDzoMDbMy = BtsyvfXcHkUanO.join(TPazCkMiYuc[7]);var Jrvdkn, LDykaNbdcMmdHw, MdhjvqVVHH" ascii
    $s7  = ") lnoywzzNIrBjIPZNjkZ += w(Jrvdkn);else if (gOTjHoGqaDKjFDNZWtpGnIs == 64) lnoywzzNIrBjIPZNjkZ += PLctiYcRAiNz(Jrvdkn, LDykaNbdc" ascii
    $s8  = "function PLctiYcRAiNz(kTiaXBOChIAxDYcitXkVMgfg,ueQlMRhxvISRLb){return String.fromCharCode(kTiaXBOChIAxDYcitXkVMgfg,ueQlMRhxvISRL" ascii
    $s9  = "function lsGOeMyISIyy(){return gDRKu(TPazCkMiYuc[13],[0,3,6],TPazCkMiYuc[14]);}" fullword ascii
    $s10 = "var DgLjzEsHCGLZhc=function(){return new ActiveXObject(TPazCkMiYuc[1]);}();" fullword ascii
    $s11 = "function PLctiYcRAiNz(kTiaXBOChIAxDYcitXkVMgfg,ueQlMRhxvISRLb){return String.fromCharCode(kTiaXBOChIAxDYcitXkVMgfg,ueQlMRhxvISRL" ascii
    $s12 = "function VzXPBbcvnEalIwRO(iRuuGBcqMUmzbTllTbI,auaocezstGjXXxEyD,MsZOtqEkHxbhq){return String.fromCharCode(iRuuGBcqMUmzbTllTbI,au" ascii
    $s13 = "MmdHw);else lnoywzzNIrBjIPZNjkZ += VzXPBbcvnEalIwRO(Jrvdkn, LDykaNbdcMmdHw, MdhjvqVVHHpCSwBdNQpWM);} while (ZmtuFdMgU < CSJlqJrF" ascii
    $s14 = "var sjjYu = DgLjzEsHCGLZhc.createtextfile(qybIUF.ExpandEnvironmentStrings(TPazCkMiYuc[3]+TPazCkMiYuc[4])+String.fromCharCode(92)" ascii
    $s15 = "function VzXPBbcvnEalIwRO(iRuuGBcqMUmzbTllTbI,auaocezstGjXXxEyD,MsZOtqEkHxbhq){return String.fromCharCode(iRuuGBcqMUmzbTllTbI,au" ascii
    $s16 = "function gDRKu(NOMpFVXUTF,qsXsQysgDfh,SbjJTqSnPxGtnn){SrsPdyCjHedO=NOMpFVXUTF.split(SbjJTqSnPxGtnn);XblvFIY = TPazCkMiYuc[0];for" ascii
    $s17 = "function RNDsSCswtKYSIMuIduH(MuhRZRgTTtgBJgP,FFATtoRfTDa){return MuhRZRgTTtgBJgP.indexOf(FFATtoRfTDa);}" fullword ascii
    $s18 = "function kwtXdhLdcl(){return gDRKu(TPazCkMiYuc[9],[1,5,7],TPazCkMiYuc[10]);}" fullword ascii
    $s19 = "function lyoitSQMdqqsvA(){return gDRKu(TPazCkMiYuc[11],[2,4,8,10],TPazCkMiYuc[12]);}" fullword ascii
    $s20 = "function RotlExxNbmO(CSJlqJrFUpGlI) {var FSDzoMDbMy = BtsyvfXcHkUanO.join(TPazCkMiYuc[7]);var Jrvdkn, LDykaNbdcMmdHw, MdhjvqVVHH" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}