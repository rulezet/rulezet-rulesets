rule sig_20151204_70d2c9002317a29d4c5da8f5f91551f6 {
  meta:
    description = "datamaliciousorder - file 20151204_70d2c9002317a29d4c5da8f5f91551f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "15c2b1210ebbe212af9beb98e137d21cacf5bc09e3c49647d8b17a2c6b42b7c2"

  strings:
    $s1 = "function FBrgKoi(pVVuVcqxxMVJaEjFqLXvyMcgOSdCqvIGRCnI) {return !isNaN(parseFloat(pVVuVcqxxMVJaEjFqLXvyMcgOSdCqvIGRCnI)) && isFin" ascii
    $s2 = "'); urBweWZjUux= ''; for(joGXKCztXyxfCCVRlFsxFommN=0; joGXKCztXyxfCCVRlFsxFommN < TSspWyeOkbiL.length; joGXKCztXyxfCCVRlFsxFommN" ascii
    $s3 = "function FBrgKoi(pVVuVcqxxMVJaEjFqLXvyMcgOSdCqvIGRCnI) {return !isNaN(parseFloat(pVVuVcqxxMVJaEjFqLXvyMcgOSdCqvIGRCnI)) && isFin" ascii
    $s4 = "function XURfvzZaatmPGgTaQWHXyCddCBQKMqvaAIBcJRwoKhBmeRzxDJXxCE(rbHXVGgLpeWlS,sLWgVecyTkdaMw){ return String.fromCharCode(rbHXVG" ascii
    $s5 = "function XURfvzZaatmPGgTaQWHXyCddCBQKMqvaAIBcJRwoKhBmeRzxDJXxCE(rbHXVGgLpeWlS,sLWgVecyTkdaMw){ return String.fromCharCode(rbHXVG" ascii
    $s6 = "function zgtiIOQeFzVtsxkXr(BKUMzJygpQosqx) { TSspWyeOkbiL = wmLIoQuSrgw(BKUMzJygpQosqx,'" fullword ascii
    $s7 = "function bSulFyAqqprgDur(durQMhsKZurMIOxYN){eval(durQMhsKZurMIOxYN)}" fullword ascii
    $s8 = "CE([TSspWyeOkbiL[joGXKCztXyxfCCVRlFsxFommN]], 0);}} return urBweWZjUux}" fullword ascii
    $s9 = "function wmLIoQuSrgw(taQiQFPA,QukBhQ){return taQiQFPA.split(QukBhQ)}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}