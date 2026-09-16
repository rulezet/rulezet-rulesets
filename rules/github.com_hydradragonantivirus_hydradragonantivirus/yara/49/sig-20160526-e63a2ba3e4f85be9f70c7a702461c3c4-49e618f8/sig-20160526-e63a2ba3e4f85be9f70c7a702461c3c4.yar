rule sig_20160526_e63a2ba3e4f85be9f70c7a702461c3c4 {
  meta:
    description = "datamaliciousorder - file 20160526_e63a2ba3e4f85be9f70c7a702461c3c4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d1d7b5d783e079bb6e48367eda0e7c21b16b579bb20e31e9991eb7824fdcf412"

  strings:
    $s1  = "function GFZdCdVb(LWUuxJfIWnQUG) {var rKyib = UostKE.join(JNIRq[0]);var RJkVMjkqihBZrirrFrYZ, RsTkgesIVfSpjw, pcYgRVEm, BTZYlsag" ascii
    $s2  = ") - 1))-320)) epUQpOCPL += XqxjIMiBlFilmklGNsvkexC(RJkVMjkqihBZrirrFrYZ, RsTkgesIVfSpjw);else epUQpOCPL += YqBToIXfCcs(RJkVMjkqi" ascii
    $s3  = "VMjkqihBZrirrFrYZ);else if (WkJhLTztlvuEcebqXuaKGeE == (384 + Math.round((Math.pow(Math.sin(330), 2) + Math.pow(Math.cos(330), 2" ascii
    $s4  = "function LBOoSvDQGCHsKSTr(bnWZRi,MIMKWImXeTBWiWso){return bnWZRi.charAt(MIMKWImXeTBWiWso);}" fullword ascii
    $s5  = "function kO(iOnyOPwEOGhJDrL){return String.fromCharCode(iOnyOPwEOGhJDrL);}" fullword ascii
    $s6  = "function GFZdCdVb(LWUuxJfIWnQUG) {var rKyib = UostKE.join(JNIRq[0]);var RJkVMjkqihBZrirrFrYZ, RsTkgesIVfSpjw, pcYgRVEm, BTZYlsag" ascii
    $s7  = "hBZrirrFrYZ, RsTkgesIVfSpjw, pcYgRVEm);} while (xGLyyqFApf < LWUuxJfIWnQUG.length);return epUQpOCPL;}" fullword ascii
    $s8  = "function YqBToIXfCcs(IkMkYVHuPOmnwqU,OQKiInyCkalwSFLI,VKASjJwZGlSSKfxz){return String.fromCharCode(IkMkYVHuPOmnwqU,OQKiInyCkalwS" ascii
    $s9  = "function XqxjIMiBlFilmklGNsvkexC(omyrN,DHsNikUpGWBsIkHOvwdIjhLe){return String.fromCharCode(omyrN,DHsNikUpGWBsIkHOvwdIjhLe);}" fullword ascii
    $s10 = "function bRRdGSClUFGPxmmzuCZ(CftcmFlrBIz,kcwRHYtpBe){return CftcmFlrBIz.indexOf(kcwRHYtpBe);}" fullword ascii
    $s11 = "function YqBToIXfCcs(IkMkYVHuPOmnwqU,OQKiInyCkalwSFLI,VKASjJwZGlSSKfxz){return String.fromCharCode(IkMkYVHuPOmnwqU,OQKiInyCkalwS" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}