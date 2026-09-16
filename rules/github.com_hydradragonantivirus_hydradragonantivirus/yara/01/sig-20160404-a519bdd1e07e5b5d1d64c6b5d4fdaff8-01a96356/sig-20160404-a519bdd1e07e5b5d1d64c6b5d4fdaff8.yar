rule sig_20160404_a519bdd1e07e5b5d1d64c6b5d4fdaff8 {
  meta:
    description = "datamaliciousorder - file 20160404_a519bdd1e07e5b5d1d64c6b5d4fdaff8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28ecc8faf7e5843f0f5e15741cb20a02e93dbeb937249664f0257bea7c24775c"

  strings:
    $s1  = "return XbFHmHf[0] + XbFHmHf[2] + XbFHmHf[4] + \".F\" + XbFHmHf[7] + XbFHmHf[9] + XbFHmHf[12] + XbFHmHf[14];" fullword ascii
    $s2  = "var bZ = true  , zsGx = agP[7] + agP[9] + agP[11];" fullword ascii
    $s3  = "ckYH.open(SRHXk,hARSs,false);" fullword ascii
    $s4  = "var XbFHmHf = TySWX(oQCemiQveN+\" \"+\"System LJ bRKsX Obj rHTBzy ect LisNJEP nLIEW\", \" \");" fullword ascii
    $s5  = "var agP = (\"2.XMLHTTP IStvsvZ xKUJc XML ream St NFEjaDTj AD luhuVQj O esZU D\").split(\" \");" fullword ascii
    $s6  = "function ZMbj(pUNsW) {" fullword ascii
    $s7  = "return \"xjUpTRBEVhinkb\";" fullword ascii
    $s8  = "function EhaxCTVCB(gGZsl) {" fullword ascii
    $s9  = "if (P >= VcrNL.length) {break;}" fullword ascii
    $s10 = "function vSpBjI(ZXkOqSx) {" fullword ascii
    $s11 = "return hZQSirH;" fullword ascii
    $s12 = "return Qkn.split(APpFr);" fullword ascii
    $s13 = "return RaznhAY;" fullword ascii
    $s14 = "function iYmI(efYHb) {" fullword ascii
    $s15 = "if (yVUkx == 503-303){return true;} else {return false;}" fullword ascii
    $s16 = "function lxri(Qfode) {" fullword ascii
    $s17 = "function LbVWoAj(YRUF) {" fullword ascii
    $s18 = "function aHzP(yVUkx) {" fullword ascii
    $s19 = "function EzSw(wNawr,hARSs,SRHXk) {" fullword ascii
    $s20 = "function NRxU(IBKGZ) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}