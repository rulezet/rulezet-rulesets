rule sig_20160310_2d43f797ba421bf10ff6e81370d5940e {
  meta:
    description = "datamaliciousorder - file 20160310_2d43f797ba421bf10ff6e81370d5940e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc7ffd43b68c65a3b4ac32d9e03fe95d5840f0628111bb135e5c009fa1e8ee90"

  strings:
    $s1  = "return SffnIpT[0] + SffnIpT[2] + SffnIpT[4] + \".F\" + SffnIpT[7] + SffnIpT[9] + SffnIpT[12] + SffnIpT[14];" fullword ascii
    $s2  = "var ex = true  , HjYH = bxw[7] + bxw[9] + bxw[11];" fullword ascii
    $s3  = "var bxw = (\"2.XMLHTTP neBfXxc eUWiE XML ream St SYJHuaON AD gVOtPPb O cRHg D\").split(\" \");" fullword ascii
    $s4  = "var SffnIpT = \"Sc ajDfDNP r CKwhsaUPK ipting PnPHvHO bsA ile NSLjUZSYhkDSxQ System jp jISti Obj NPyBju ect PuYbgHm\".split(\" " ascii
    $s5  = "BuZjB.open(jLFxg,NQpLX,false);" fullword ascii
    $s6  = "function Ugpj(BuZjB,NQpLX,jLFxg) {" fullword ascii
    $s7  = "return iJzLmck" fullword ascii
    $s8  = "function DHkTiOSu(tyP) {" fullword ascii
    $s9  = "return xNzk.responseBody;" fullword ascii
    $s10 = "function KiFdpYD(xNzk) {" fullword ascii
    $s11 = "function Iozk(iZGUy) {" fullword ascii
    $s12 = "return oXdYW.status;" fullword ascii
    $s13 = "function qwTD(PHyGA) {" fullword ascii
    $s14 = "function MzKp(ytYkk) {" fullword ascii
    $s15 = "function nujFiTG(ctnL,AAgDD) {" fullword ascii
    $s16 = "dam = Q; break; " fullword ascii
    $s17 = "function KCfi(vwHOH,gAcqq) {" fullword ascii
    $s18 = "return ctnL.ExpandEnvironmentStrings(AAgDD);" fullword ascii
    $s19 = "return ZopfR;" fullword ascii
    $s20 = "function zvSj(MuVgl) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}