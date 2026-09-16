rule sig_20160313_1928ab5a67eb0b8c8dca354241a9dbe8 {
  meta:
    description = "datamaliciousorder - file 20160313_1928ab5a67eb0b8c8dca354241a9dbe8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbcd6676380cdbea490a1c9864b8ff68c54b76464ebca8c68bbdc830b9145e78"

  strings:
    $s1  = "return ElFGzfU[0] + ElFGzfU[2] + ElFGzfU[4] + \".F\" + ElFGzfU[7] + ElFGzfU[9] + ElFGzfU[12] + ElFGzfU[14];" fullword ascii
    $s2  = "var rA = true  , izQJ = mPi[7] + mPi[9] + mPi[11];" fullword ascii
    $s3  = "var mPi = (\"2.XMLHTTP pfjEjhn MWDrM XML ream St IPSvbzeX AD Orhfpkk O rwsz D\").split(\" \");" fullword ascii
    $s4  = "Edwec.open(PNsBR,DuoDB,false);" fullword ascii
    $s5  = "function tRxyM(OjFnwC) {" fullword ascii
    $s6  = "function BEtmYvYJ(RPb) {" fullword ascii
    $s7  = "if(W>=r.length) {break;}" fullword ascii
    $s8  = "function sfnkFGPn() {" fullword ascii
    $s9  = "function TXZo(Tosoq) {" fullword ascii
    $s10 = "function MZFU(Edwec,DuoDB,PNsBR) {" fullword ascii
    $s11 = "if (GVxkC > 173530-293){return true;} else {return false;}" fullword ascii
    $s12 = "function jZUI(cUKHg) {" fullword ascii
    $s13 = "return UmSy.ExpandEnvironmentStrings(rPlXY);" fullword ascii
    $s14 = "function xAEJQCz(ejzv) {" fullword ascii
    $s15 = "function IPgX(GVxkC) {" fullword ascii
    $s16 = "function lvOl(MjcMR,kKhNG) {" fullword ascii
    $s17 = "if (c >= dqHlo.length) {break;}" fullword ascii
    $s18 = "function SsVjA(tdkhfe) {" fullword ascii
    $s19 = "return new ActiveXObject(tdkhfe);" fullword ascii
    $s20 = "function jvMvSsr(UmSy,rPlXY) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}