rule sig_20160405_eaa78364a4c4487d358d3cb685851e3f {
  meta:
    description = "datamaliciousorder - file 20160405_eaa78364a4c4487d358d3cb685851e3f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6616ae30ac8165944fb55036fdf21a295fdc3d64bf5ce902d1e55f0c1fe74b5b"

  strings:
    $s1  = "var mH = true  , SJka = Lnw[7] + Lnw[9] + Lnw[11];" fullword ascii
    $s2  = "return TIRAGUU[0] + TIRAGUU[2] + TIRAGUU[4] + \".F\" + TIRAGUU[7] + TIRAGUU[9] + TIRAGUU[12] + TIRAGUU[14];" fullword ascii
    $s3  = "JCJb.open(txfhB,QHoSb,false);" fullword ascii
    $s4  = "var Lnw = (\"2.XMLHTTP yThXEWx QJSRo XML ream St BJlImoVb AD qPdrjFt O YPYJ D\").split(\" \");" fullword ascii
    $s5  = "if(o>=g.length) {break;}" fullword ascii
    $s6  = "acl = o; break; " fullword ascii
    $s7  = "function vEhvJ(iNaaEn) {" fullword ascii
    $s8  = "return HJMik.status;" fullword ascii
    $s9  = "function XRLWSNtQ(guaB) {" fullword ascii
    $s10 = "function AgMe(jRjAz) {" fullword ascii
    $s11 = "function YAlrpEpCZ(RZrCCkTDfZf) {" fullword ascii
    $s12 = "function VSFZ(HJMik) {" fullword ascii
    $s13 = "function Vtcpags(zCEQ,vScer) {" fullword ascii
    $s14 = "function ebrZH(hGFfOh) {" fullword ascii
    $s15 = "function VRDh(TiCbi) {" fullword ascii
    $s16 = "function Ysho(GolfB) {" fullword ascii
    $s17 = "function lplr(Kyhes) {" fullword ascii
    $s18 = "return BIo.split(wvzDR);" fullword ascii
    $s19 = "function rlqy(iHSUg,PrEaG) {" fullword ascii
    $s20 = "function smSycYKtm(PMsUH) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}