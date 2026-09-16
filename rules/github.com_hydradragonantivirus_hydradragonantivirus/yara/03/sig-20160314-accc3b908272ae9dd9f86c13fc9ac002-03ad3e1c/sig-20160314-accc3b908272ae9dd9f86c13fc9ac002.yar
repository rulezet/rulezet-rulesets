rule sig_20160314_accc3b908272ae9dd9f86c13fc9ac002 {
  meta:
    description = "datamaliciousorder - file 20160314_accc3b908272ae9dd9f86c13fc9ac002.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f0ab409dcb55d261a7caa1c0293dc5fe197697b462bfcb6c3cfdd99b37a3f1d"

  strings:
    $s1  = "var Jx = true  , EBcW = efW[7] + efW[9] + efW[11];" fullword ascii
    $s2  = "return kQDmfnH[0] + kQDmfnH[2] + kQDmfnH[4] + \".F\" + kQDmfnH[7] + kQDmfnH[9] + kQDmfnH[12] + kQDmfnH[14];" fullword ascii
    $s3  = "aFMNx.open(LcWms,JOHyx,false);" fullword ascii
    $s4  = "var kQDmfnH = \"Sc QRsaRap r yPJPzNeEq ipting mxoHVTw Ifk ile DigeHbrPleqaEJ System Hr hWcwm Obj UaMVWV ect OJhOAFt uxnGt\".spli" ascii
    $s5  = "var efW = (\"2.XMLHTTP QhPcBWb XaFPI XML ream St yqMxkwAV AD IxwMLsm O lUfq D\").split(\" \");" fullword ascii
    $s6  = "var kQDmfnH = \"Sc QRsaRap r yPJPzNeEq ipting mxoHVTw Ifk ile DigeHbrPleqaEJ System Hr hWcwm Obj UaMVWV ect OJhOAFt uxnGt\".spli" ascii
    $s7  = "function cJWFc(zONNco) {" fullword ascii
    $s8  = "function joguWJE(ezom) {" fullword ascii
    $s9  = "function MCCBiHxv(vks) {" fullword ascii
    $s10 = "if (GDOHi == 904-704){return true;} else {return false;}" fullword ascii
    $s11 = "function mvuFW(mKcLok) {" fullword ascii
    $s12 = "return new ActiveXObject(zONNco);" fullword ascii
    $s13 = "function HWVWShP(IUvy,kPGWU) {" fullword ascii
    $s14 = "function QyLraPujw() {" fullword ascii
    $s15 = "function WNYS(aFMNx,JOHyx,LcWms) {" fullword ascii
    $s16 = "function HUfi(GDOHi) {" fullword ascii
    $s17 = "function kLtt(TvQzs) {" fullword ascii
    $s18 = "function Vppe(UTydV) {" fullword ascii
    $s19 = "function RFkngbHn() {" fullword ascii
    $s20 = "function GRSK(qDxTs) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}