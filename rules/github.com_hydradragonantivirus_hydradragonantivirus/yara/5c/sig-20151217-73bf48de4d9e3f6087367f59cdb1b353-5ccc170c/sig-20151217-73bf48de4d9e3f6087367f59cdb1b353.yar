rule sig_20151217_73bf48de4d9e3f6087367f59cdb1b353 {
  meta:
    description = "datamaliciousorder - file 20151217_73bf48de4d9e3f6087367f59cdb1b353.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c52bc4442959df717565e47ad6ae61d97545e326e5ea8c7d303b01102100813a"

  strings:
    $s1  = "th.pow(Math.cos(316), 2) - 1)); while(true) { if(RrYJOPKQD[aAWDtJIfyAb] > hmCPm[aAWDtJIfyAb].length-(148+200)/348) { break; } if" ascii
    $s2  = "function LmqhJbCftucEhzKoe(hmCPm){jUlPFaLTUWC= '';aAWDtJIfyAb=Math.round((Math.pow(Math.sin(443), 2) + Math.pow(Math.cos(443), 2" ascii
    $s3  = ") - 1));while(true){if (aAWDtJIfyAb >= (2882+946)/638){break;}RrYJOPKQD[aAWDtJIfyAb]=Math.round((Math.pow(Math.sin(316), 2) + Ma" ascii
    $s4  = "pow(Math.cos(941), 2) - 1)));} RrYJOPKQD[aAWDtJIfyAb]++;}aAWDtJIfyAb++;} return jUlPFaLTUWC}" fullword ascii
    $s5  = "UjXMHNkOROtnXnzkZsmMrpMVlRtIVVqgFVU([hmCPm[aAWDtJIfyAb][RrYJOPKQD[aAWDtJIfyAb]]], Math.round((Math.pow(Math.sin(941), 2) + Math." ascii
    $s6  = "function LmqhJbCftucEhzKoe(hmCPm){jUlPFaLTUWC= '';aAWDtJIfyAb=Math.round((Math.pow(Math.sin(443), 2) + Math.pow(Math.cos(443), 2" ascii
    $s7  = "var w = new Array();w[0]=[];w[0][0]='d';w[0][1]='a';w[0][2]='d';w[0][3]='a';w[0][4]='46';w[0][5]='3d';w[0][6]='42';w[0][7]='14';" ascii
    $s8  = "function Z(zKJKcTacGWiKJY,FeCniTVcVkxJu,CgIksKsiZuj) {zKJKcTacGWiKJY[FeCniTVcVkxJu]=CgIksKsiZuj;}" fullword ascii
    $s9  = "function jcmoInPDrGHiSmifAADUjXMHNkOROtnXnzkZsmMrpMVlRtIVVqgFVU(TDYiwWvqOFIfj,DyCSfBIgmOivKI){ return llGRfUs[HyRmzUxf[mFnUZ(TDY" ascii
    $s10 = "var w = new Array();w[0]=[];w[0][0]='d';w[0][1]='a';w[0][2]='d';w[0][3]='a';w[0][4]='46';w[0][5]='3d';w[0][6]='42';w[0][7]='14';" ascii
    $s11 = "function mFnUZ(naSTGbhQRye,JDTTMSdQtulAm,tgtkpVWf){UIJZ=GNXAeTjESXNEZeQsb(naSTGbhQRye,JDTTMSdQtulAm);fpbdn=UIJZ.toString(tgtkpVW" ascii
    $s12 = "function mFnUZ(naSTGbhQRye,JDTTMSdQtulAm,tgtkpVWf){UIJZ=GNXAeTjESXNEZeQsb(naSTGbhQRye,JDTTMSdQtulAm);fpbdn=UIJZ.toString(tgtkpVW" ascii
    $s13 = "function IAazXAAWsEhefTF(rpEpBWuOoPFJImngXHa) {return parseFloat(rpEpBWuOoPFJImngXHa);}" fullword ascii
    $s14 = "function n(CeIexgtcUByW,MvkFaxrzhKFqkx){CeIexgtcUByW.push(MvkFaxrzhKFqkx);}" fullword ascii
    $s15 = "f);return fpbdn;}" fullword ascii
    $s16 = "function GKELzouNvcvXxfs(wLWncMHYZCfnwGRpm,ZubrzGKlJBooyqlvkJKWgEFBUGSdrFELfV,EGsEnpZogEEPOqzObbRsEDbOKyltTaeClIq){eval(wLWncMHY" ascii
    $s17 = "function fvQLiATlzap(MSoiVDFskdRkVy) {return isNaN(MSoiVDFskdRkVy);}" fullword ascii
    $s18 = ",'>','V','-','V','/','Q','u','%','W','b','e','X','+','z','.','0','*','Y','7','Z','p',',','C','.','[','%','q','H','i','F',String." ascii
    $s19 = "function jcmoInPDrGHiSmifAADUjXMHNkOROtnXnzkZsmMrpMVlRtIVVqgFVU(TDYiwWvqOFIfj,DyCSfBIgmOivKI){ return llGRfUs[HyRmzUxf[mFnUZ(TDY" ascii
    $s20 = "function GNXAeTjESXNEZeQsb(AKskXCJNBE,wDwwdJZApH) {return parseInt(AKskXCJNBE,wDwwdJZApH);}" fullword ascii

  condition:
    uint16(0) == 0x7948 and
    8 of them
}