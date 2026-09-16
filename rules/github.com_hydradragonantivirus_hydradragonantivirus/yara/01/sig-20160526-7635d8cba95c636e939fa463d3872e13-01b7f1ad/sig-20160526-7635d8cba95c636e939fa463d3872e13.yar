rule sig_20160526_7635d8cba95c636e939fa463d3872e13 {
  meta:
    description = "datamaliciousorder - file 20160526_7635d8cba95c636e939fa463d3872e13.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9db26eb5fe1d39bdf7d9564259794a465c28b5d1b7e8ac47b4a78ae240bb36da"

  strings:
    $s1  = "aPlFv += Sc(kEOyhRvFwPDQltcSnAS);else if (LZFbJtuUDK == (812 + Math.round((Math.pow(Math.sin(169), 2) + Math.pow(Math.cos(169), " ascii
    $s2  = "function irXyakzz(mpOmzOlVMPKiB) {var IDElxoXTtPgaTtGqtFSMCiGL = mTBrY.join(xkeSRlhzQCOU[0]);var kEOyhRvFwPDQltcSnAS, wnEBEo, lR" ascii
    $s3  = "function KPxDFLgAZkTr(szQXxnupwp,uoVsgdgOOLTq){return szQXxnupwp.charAt(uoVsgdgOOLTq);}" fullword ascii
    $s4  = "2) - 1))-748)) BKywtaUCaPlFv += PYefPKqHJjhxw(kEOyhRvFwPDQltcSnAS, wnEBEo);else BKywtaUCaPlFv += ZKTraKEqaYa(kEOyhRvFwPDQltcSnAS" ascii
    $s5  = "function PYefPKqHJjhxw(txRZycIIGzEyjX,pRkqsVFg){return String.fromCharCode(txRZycIIGzEyjX,pRkqsVFg);}" fullword ascii
    $s6  = "function YErVryvMAHQGIDteXieWpK(PeNlxe,yQcJY){return PeNlxe.indexOf(yQcJY);}" fullword ascii
    $s7  = "function Sc(UChTdVUNmIHMF){return String.fromCharCode(UChTdVUNmIHMF);}" fullword ascii
    $s8  = "function ZKTraKEqaYa(AywpFaLRezDcvq,ckROszyKfuZycSBdORWnIJKu,Pqurgul){return String.fromCharCode(AywpFaLRezDcvq,ckROszyKfuZycSBd" ascii
    $s9  = "function ZKTraKEqaYa(AywpFaLRezDcvq,ckROszyKfuZycSBdORWnIJKu,Pqurgul){return String.fromCharCode(AywpFaLRezDcvq,ckROszyKfuZycSBd" ascii
    $s10 = "function irXyakzz(mpOmzOlVMPKiB) {var IDElxoXTtPgaTtGqtFSMCiGL = mTBrY.join(xkeSRlhzQCOU[0]);var kEOyhRvFwPDQltcSnAS, wnEBEo, lR" ascii
    $s11 = ", wnEBEo, lRodoZqVotXIGc);} while (DOHNYGZHredgLiEZm < mpOmzOlVMPKiB.length);return BKywtaUCaPlFv;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}