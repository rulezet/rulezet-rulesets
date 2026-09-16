rule sig_20160526_def4ee5572908a5ead45ff34f41d084a {
  meta:
    description = "datamaliciousorder - file 20160526_def4ee5572908a5ead45ff34f41d084a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85c8f5119c23138795d8f88f7443e4a07e06b28e447fad6f1a12168dc55eefe6"

  strings:
    $s1  = "function sJhmyrA(GwolNskgkUNtj) {var afIQxqEyJQj = pKdORO.join(UPaYwJUEV[0]);var VzVHfrHXHEjPASyNeqLhse, mVcVIFSGtMmnwRcbih, QtJ" ascii
    $s2  = "cos(612), 2) - 1))-509)) fkbeqGkqUzVytYFCgC += TUmVshpyJIQsBeMNmntjlrF(VzVHfrHXHEjPASyNeqLhse, mVcVIFSGtMmnwRcbih);else fkbeqGkq" ascii
    $s3  = "YFCgC += wE(VzVHfrHXHEjPASyNeqLhse);else if (CLIgsbWbOjCjqbRYG == (573 + Math.round((Math.pow(Math.sin(612), 2) + Math.pow(Math." ascii
    $s4  = "function eUWaqXroiyOkmOhLKcUjT(ZDWOTiXGoU,yuzipKnsugRNXa){return ZDWOTiXGoU.charAt(yuzipKnsugRNXa);}" fullword ascii
    $s5  = "function CGyyznrTkEwgJmEmcReCJK(lYocIJGSPrHgbICQmTMPbrY,UFODy){return lYocIJGSPrHgbICQmTMPbrY.indexOf(UFODy);}" fullword ascii
    $s6  = "Ntj.length);return fkbeqGkqUzVytYFCgC;}" fullword ascii
    $s7  = "function sJhmyrA(GwolNskgkUNtj) {var afIQxqEyJQj = pKdORO.join(UPaYwJUEV[0]);var VzVHfrHXHEjPASyNeqLhse, mVcVIFSGtMmnwRcbih, QtJ" ascii
    $s8  = "UzVytYFCgC += KbqNPpdmPvTIcFtHaphZBF(VzVHfrHXHEjPASyNeqLhse, mVcVIFSGtMmnwRcbih, QtJQB);} while (vUYjELsthnEFirpLBT < GwolNskgkU" ascii
    $s9  = "function KbqNPpdmPvTIcFtHaphZBF(FyWDbaPNS,BeTWHEj,xKGJBmoxQKbKQjeubuRnWabT){return String.fromCharCode(FyWDbaPNS,BeTWHEj,xKGJBmo" ascii
    $s10 = "function wE(XqahILPiBoycHykvgx){return String.fromCharCode(XqahILPiBoycHykvgx);}" fullword ascii
    $s11 = "function TUmVshpyJIQsBeMNmntjlrF(fQbWEhpGq,AZWAFHbiSTtGv){return String.fromCharCode(fQbWEhpGq,AZWAFHbiSTtGv);}" fullword ascii
    $s12 = "function KbqNPpdmPvTIcFtHaphZBF(FyWDbaPNS,BeTWHEj,xKGJBmoxQKbKQjeubuRnWabT){return String.fromCharCode(FyWDbaPNS,BeTWHEj,xKGJBmo" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}