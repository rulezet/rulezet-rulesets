rule sig_20160525_244e06053504b4c1c7963a5bd158bdc6 {
  meta:
    description = "datamaliciousorder - file 20160525_244e06053504b4c1c7963a5bd158bdc6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72e03b718cdb940ee10bef760076e865f580115f3feb8015c1a9672d117aca34"

  strings:
    $s1  = ".pow(Math.cos(291), 2) - 1))-848)) DHXZQsLVtlw += MrGfk(GPgNpWdz, kNuhIUBcouQZQcNqRXdrt);else DHXZQsLVtlw += ZWZPPBUHgWbDPCJEub(" ascii
    $s2  = "function hUKSomDaH(BRbJlWRxgTrlb) {var MtKnbtk = YQodxjFTosfoKtS.join(vBOgQfNiAmNGTdhOfNfwSWbP[0]);var GPgNpWdz, kNuhIUBcouQZQcN" ascii
    $s3  = "6), 2) - 1))-321)) DHXZQsLVtlw += M(GPgNpWdz);else if (GOYIMvnhdedCyhMfz == (912 + Math.round((Math.pow(Math.sin(291), 2) + Math" ascii
    $s4  = "function tWsqQyJcdZCfZZT(FRccDOi,rUlfDqUdrYzCbzHBvqXuNQw){return FRccDOi.charAt(rUlfDqUdrYzCbzHBvqXuNQw);}" fullword ascii
    $s5  = "function MrGfk(ZbkAvrJghLKcQMGK,ulQtUXzGM){return String.fromCharCode(ZbkAvrJghLKcQMGK,ulQtUXzGM);}" fullword ascii
    $s6  = "function hUKSomDaH(BRbJlWRxgTrlb) {var MtKnbtk = YQodxjFTosfoKtS.join(vBOgQfNiAmNGTdhOfNfwSWbP[0]);var GPgNpWdz, kNuhIUBcouQZQcN" ascii
    $s7  = "GPgNpWdz, kNuhIUBcouQZQcNqRXdrt, TAEyjyHpJVQOpFYGUflxWM);} while (FlBPuqwsgxmWHhJ < BRbJlWRxgTrlb.length);return DHXZQsLVtlw;}" fullword ascii
    $s8  = "function lvSxscxGaUTGTLCbs(YGuUICjkxWKz,dowoqTHwCVwUUJwmqkG){return YGuUICjkxWKz.indexOf(dowoqTHwCVwUUJwmqkG);}" fullword ascii
    $s9  = "function M(TMaEmcmXHrOlpsI){return String.fromCharCode(TMaEmcmXHrOlpsI);}" fullword ascii
    $s10 = "function ZWZPPBUHgWbDPCJEub(zFTVA,zMgCdbNkcYvUskb,HjgjXryNlCAzHtjVXsUGPFJv){return String.fromCharCode(zFTVA,zMgCdbNkcYvUskb,Hjg" ascii
    $s11 = "function ZWZPPBUHgWbDPCJEub(zFTVA,zMgCdbNkcYvUskb,HjgjXryNlCAzHtjVXsUGPFJv){return String.fromCharCode(zFTVA,zMgCdbNkcYvUskb,Hjg" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}