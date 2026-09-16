rule sig_20151217_f74387f954c8d77201a707c543436f71 {
  meta:
    description = "datamaliciousorder - file 20151217_f74387f954c8d77201a707c543436f71.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ca0ea4ef9bd471e649805b3ef0ac85f1175c6bd3cf6140368cbf5c8a0b2c0e4"

  strings:
    $s1  = ") - 1));while(true){if (vOBNTwNklIc >= (3505+227)/622){break;}bSVimnyvr[vOBNTwNklIc]=Math.round((Math.pow(Math.sin(325), 2) + Ma" ascii
    $s2  = "(Math.cos(47), 2) - 1)));} bSVimnyvr[vOBNTwNklIc]++;}vOBNTwNklIc++;} return qIdxqyBrDjC}" fullword ascii
    $s3  = "th.pow(Math.cos(325), 2) - 1)); while(true) { if(bSVimnyvr[vOBNTwNklIc] > TErdo[vOBNTwNklIc].length-(42+357)/399) { break; } if " ascii
    $s4  = "function ZlAEwAQsuESaOeOtI(TErdo){qIdxqyBrDjC= '';vOBNTwNklIc=Math.round((Math.pow(Math.sin(151), 2) + Math.pow(Math.cos(151), 2" ascii
    $s5  = "function ZlAEwAQsuESaOeOtI(TErdo){qIdxqyBrDjC= '';vOBNTwNklIc=Math.round((Math.pow(Math.sin(151), 2) + Math.pow(Math.cos(151), 2" ascii
    $s6  = "function jimhoCc(uuTTCwCScWHMRCJFALGHUVMVnsliEswiAcBt) {return !THaSTaPdaul(gNZHSmyakgvPNJg(uuTTCwCScWHMRCJFALGHUVMVnsliEswiAcBt" ascii
    $s7  = "var J = new Array();J[0]=[];J[0][0]='d';J[0][1]='a';J[0][2]='d';J[0][3]='a';J[0][4]='46';J[0][5]='3d';J[0][6]='42';J[0][7]='14';" ascii
    $s8  = ",'j','.','e','V',']','M','(','W','4','x','T','t','<','X','m','Y',']','<','t','Q','R','Z','J','(','[','y','h','+','k','Y',String." ascii
    $s9  = "function jimhoCc(uuTTCwCScWHMRCJFALGHUVMVnsliEswiAcBt) {return !THaSTaPdaul(gNZHSmyakgvPNJg(uuTTCwCScWHMRCJFALGHUVMVnsliEswiAcBt" ascii
    $s10 = "function kzSFG(SNZHSVoYBkQ,uIapubDZjfhPA,TPqesubO){ufiL=LjqsYifNgTvzDaixE(SNZHSVoYBkQ,uIapubDZjfhPA);ZzcEC=ufiL.toString(TPqesub" ascii
    $s11 = "function LjqsYifNgTvzDaixE(cSeNVhBhMK,SwgAQQfUVZ) {return parseInt(cSeNVhBhMK,SwgAQQfUVZ);}" fullword ascii
    $s12 = "function THaSTaPdaul(LheoKBeylFrSHE) {return isNaN(LheoKBeylFrSHE);}" fullword ascii
    $s13 = "function zwTDRCqVHQSKBlS(wCdXBvQQWlUfhLiUH,BdrPpikcpzJySlWcGVGnAWcYxxjUJihwCj,lDTYQZjFqMqyFvCjUjotefHnpmLvuWOwgPo){eval(wCdXBvQQ" ascii
    $s14 = "function gdalRXzcqPIk(AmlfftFchTFXr) {return isFinite(AmlfftFchTFXr);}" fullword ascii
    $s15 = "function gNZHSmyakgvPNJg(yzEjNIoGqTztglvKtar) {return parseFloat(yzEjNIoGqTztglvKtar);}" fullword ascii
    $s16 = "O);return ZzcEC;}" fullword ascii
    $s17 = "function zwTDRCqVHQSKBlS(wCdXBvQQWlUfhLiUH,BdrPpikcpzJySlWcGVGnAWcYxxjUJihwCj,lDTYQZjFqMqyFvCjUjotefHnpmLvuWOwgPo){eval(wCdXBvQQ" ascii
    $s18 = "var J = new Array();J[0]=[];J[0][0]='d';J[0][1]='a';J[0][2]='d';J[0][3]='a';J[0][4]='46';J[0][5]='3d';J[0][6]='42';J[0][7]='14';" ascii
    $s19 = "function kzSFG(SNZHSVoYBkQ,uIapubDZjfhPA,TPqesubO){ufiL=LjqsYifNgTvzDaixE(SNZHSVoYBkQ,uIapubDZjfhPA);ZzcEC=ufiL.toString(TPqesub" ascii
    $s20 = "function lcZHydXDaKljGIJyDbyoitezvAMXlkYbssbaGDZAOWvwYUdUUbVYBW(ltynTgbkXqljP,icibBrVMXjkdEm){ return EldXhyt[afYsxuCu[kzSFG(lty" ascii

  condition:
    uint16(0) == 0x6661 and
    8 of them
}