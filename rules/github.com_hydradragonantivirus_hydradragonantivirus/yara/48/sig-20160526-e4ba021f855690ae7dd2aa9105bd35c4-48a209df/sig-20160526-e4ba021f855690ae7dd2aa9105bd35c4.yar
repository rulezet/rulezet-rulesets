rule sig_20160526_e4ba021f855690ae7dd2aa9105bd35c4 {
  meta:
    description = "datamaliciousorder - file 20160526_e4ba021f855690ae7dd2aa9105bd35c4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92b23208a29c996fb38468800518c03186103da20882f733b935f7b3ac586808"

  strings:
    $s1  = "9), 2) - 1))-319)) CAuPbqAQfmnPHmwUOcMbCZ += u(cQqvWIofJURCNrkTUe);else if (EcTFKtZbmOVCTu == (476 + Math.round((Math.pow(Math.s" ascii
    $s2  = "function wxhiBxkayysY(ZLJtDsShwJHzS) {var XCtMiYDrQ = kMFlPTxDsuNdVhQygebKi.join(vwMbhGwsWYR[0]);var cQqvWIofJURCNrkTUe, pPjteWX" ascii
    $s3  = "function mzLgQvKJGdwwvUfvZ(mCENUcFnHZj,pvZXuIVIVGQiDfpl){return mCENUcFnHZj.charAt(pvZXuIVIVGQiDfpl);}" fullword ascii
    $s4  = "function vcpORWcjeaNZxonCNxqFDJI(dQzbWdPkerKcEFiCqrTGJBrP,RjKMHwtjCWngWBovxRYxD,WmKTbLMS){return String.fromCharCode(dQzbWdPkerK" ascii
    $s5  = "function JGVFCMSuLJesEA(OrGyaXgJhqcjAzSuxT,pPmlD){return String.fromCharCode(OrGyaXgJhqcjAzSuxT,pPmlD);}" fullword ascii
    $s6  = "function wxhiBxkayysY(ZLJtDsShwJHzS) {var XCtMiYDrQ = kMFlPTxDsuNdVhQygebKi.join(vwMbhGwsWYR[0]);var cQqvWIofJURCNrkTUe, pPjteWX" ascii
    $s7  = "function mjAMDDQfPmptgT(KXnLcX,bIrqfRsSzREOOqftigoMRY){return KXnLcX.indexOf(bIrqfRsSzREOOqftigoMRY);}" fullword ascii
    $s8  = "function vcpORWcjeaNZxonCNxqFDJI(dQzbWdPkerKcEFiCqrTGJBrP,RjKMHwtjCWngWBovxRYxD,WmKTbLMS){return String.fromCharCode(dQzbWdPkerK" ascii
    $s9  = "function u(JGNuOtQX){return String.fromCharCode(JGNuOtQX);}" fullword ascii
    $s10 = "qkIneHxA);} while (DATixdDXGsubPnNJ < ZLJtDsShwJHzS.length);return CAuPbqAQfmnPHmwUOcMbCZ;}" fullword ascii
    $s11 = "cxzclGYNTP);else CAuPbqAQfmnPHmwUOcMbCZ += vcpORWcjeaNZxonCNxqFDJI(cQqvWIofJURCNrkTUe, pPjteWXkNXOKoecxzclGYNTP, pQQsJdFXEECXrcp" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}