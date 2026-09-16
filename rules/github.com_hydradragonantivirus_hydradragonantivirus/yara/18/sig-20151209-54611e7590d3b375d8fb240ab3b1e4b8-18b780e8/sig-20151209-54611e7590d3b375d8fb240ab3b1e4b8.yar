rule sig_20151209_54611e7590d3b375d8fb240ab3b1e4b8 {
  meta:
    description = "datamaliciousorder - file 20151209_54611e7590d3b375d8fb240ab3b1e4b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea90a768b1eb634fca6c6376bc3bab24a64e2798238aa30ca0012d416b7c9b0d"

  strings:
    $s1  = "function XvCVmYp(pCgdUItsncqAALIzVRDMLRFHUrvzDksLUUTf) {return !isNaN(parseFloat(pCgdUItsncqAALIzVRDMLRFHUrvzDksLUUTf)) && isFin" ascii
    $s2  = "function XvCVmYp(pCgdUItsncqAALIzVRDMLRFHUrvzDksLUUTf) {return !isNaN(parseFloat(pCgdUItsncqAALIzVRDMLRFHUrvzDksLUUTf)) && isFin" ascii
    $s3  = " lrrgl;}function pWDBZCzPEHJLWkJ(snFcdsAUqMdpBLKFi){eval(snFcdsAUqMdpBLKFi)}" fullword ascii
    $s4  = ";}} return PDjtpHwKoaI}" fullword ascii
    $s5  = "function XpoBg(tvkxGkYjkOr,uRNLxdRfXkNIZ,UblqZQWc){croV=parseInt(tvkxGkYjkOr,uRNLxdRfXkNIZ);lrrgl=croV.toString(UblqZQWc);return" ascii
    $s6  = "function XKEwkvScTAZoxFaCYMfxdoLWzqRTKoovnAPGPwprTdTlDfJkfkXGUA(LShNLOQSSnVGd,FnPePzuJkVTsSA){ return oTxSb[XpoBg(LShNLOQSSnVGd[" ascii
    $s7  = "function FFIjVtqbgWt(qGFhlDch,zQsaPI){return qGFhlDch.split(zQsaPI)}" fullword ascii
    $s8  = "function OxOdcLUbIQSxltbLA(opaiX){PDjtpHwKoaI= '';for(VJXduMkQKgk=(-975+975)/292; VJXduMkQKgk < (235+953)/594; VJXduMkQKgk++) {I" ascii
    $s9  = "function XKEwkvScTAZoxFaCYMfxdoLWzqRTKoovnAPGPwprTdTlDfJkfkXGUA(LShNLOQSSnVGd,FnPePzuJkVTsSA){ return oTxSb[XpoBg(LShNLOQSSnVGd[" ascii
    $s10 = "function XpoBg(tvkxGkYjkOr,uRNLxdRfXkNIZ,UblqZQWc){croV=parseInt(tvkxGkYjkOr,uRNLxdRfXkNIZ);lrrgl=croV.toString(UblqZQWc);return" ascii
    $s11 = "ObhLtTCA[VJXduMkQKgk]=(-423+423)/327; while(true) { if(IObhLtTCA[VJXduMkQKgk] > opaiX[VJXduMkQKgk].length-(359+425)/784) { break" ascii
    $s12 = "function OxOdcLUbIQSxltbLA(opaiX){PDjtpHwKoaI= '';for(VJXduMkQKgk=(-975+975)/292; VJXduMkQKgk < (235+953)/594; VJXduMkQKgk++) {I" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}