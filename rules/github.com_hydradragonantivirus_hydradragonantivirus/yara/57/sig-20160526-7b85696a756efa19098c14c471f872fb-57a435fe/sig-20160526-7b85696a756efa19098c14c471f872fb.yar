rule sig_20160526_7b85696a756efa19098c14c471f872fb {
  meta:
    description = "datamaliciousorder - file 20160526_7b85696a756efa19098c14c471f872fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c897a93c34313bc7016533584d541437193a9591d40b44630184da6c741bd29"

  strings:
    $s1  = "function HRtbpszi(KKnrdGFFKRnMd) {var Mvhnd = YktCErdJphWfLwY.join(BnhBbvJzXaRiYKyRIWv[0]);var EXJXEeOa, tuSmHIrNCz, vfnJzVeRBHI" ascii
    $s2  = "function vyjvSMfwGZVpqUWGuumvv(iPEsFuQfwpkNCYoHIScKQNPZ,gOyzOzweHMseZFUa){return iPEsFuQfwpkNCYoHIScKQNPZ.charAt(gOyzOzweHMseZFU" ascii
    $s3  = "function vyjvSMfwGZVpqUWGuumvv(iPEsFuQfwpkNCYoHIScKQNPZ,gOyzOzweHMseZFUa){return iPEsFuQfwpkNCYoHIScKQNPZ.charAt(gOyzOzweHMseZFU" ascii
    $s4  = "s(910), 2) - 1))-588)) BisgteWUEcaJhoPgurHY += whCSUUYTGEAxSW(EXJXEeOa, tuSmHIrNCz);else BisgteWUEcaJhoPgurHY += OriiQAwjXmoceMs" ascii
    $s5  = "teWUEcaJhoPgurHY += r(EXJXEeOa);else if (VNXMYlCePMzFVfgKcVC == (652 + Math.round((Math.pow(Math.sin(910), 2) + Math.pow(Math.co" ascii
    $s6  = "function r(GRftmQxTdKMZSIspw){return String.fromCharCode(GRftmQxTdKMZSIspw);}" fullword ascii
    $s7  = "function whCSUUYTGEAxSW(ZxRsoxegxFfrsTTnfvVafLi,lXzzXuOBJHkpk){return String.fromCharCode(ZxRsoxegxFfrsTTnfvVafLi,lXzzXuOBJHkpk)" ascii
    $s8  = "function HRtbpszi(KKnrdGFFKRnMd) {var Mvhnd = YktCErdJphWfLwY.join(BnhBbvJzXaRiYKyRIWv[0]);var EXJXEeOa, tuSmHIrNCz, vfnJzVeRBHI" ascii
    $s9  = "function vMqotwcErqpLojRpNymcLANJ(xYlVnOKEAGJKGwksyn,mXcYRD){return xYlVnOKEAGJKGwksyn.indexOf(mXcYRD);}" fullword ascii
    $s10 = "function whCSUUYTGEAxSW(ZxRsoxegxFfrsTTnfvVafLi,lXzzXuOBJHkpk){return String.fromCharCode(ZxRsoxegxFfrsTTnfvVafLi,lXzzXuOBJHkpk)" ascii
    $s11 = "function OriiQAwjXmoceMsUHssqUcDG(CADtYhdsjgW,dadpcHvhSOpqNWHxZufoiV,jUMJrXCimtUACZzsuegq){return String.fromCharCode(CADtYhdsjg" ascii
    $s12 = "UHssqUcDG(EXJXEeOa, tuSmHIrNCz, vfnJzVeRBHIxTnuXzoyGvyk);} while (uubOuYfBKdYnteL < KKnrdGFFKRnMd.length);return BisgteWUEcaJhoP" ascii
    $s13 = "function OriiQAwjXmoceMsUHssqUcDG(CADtYhdsjgW,dadpcHvhSOpqNWHxZufoiV,jUMJrXCimtUACZzsuegq){return String.fromCharCode(CADtYhdsjg" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}