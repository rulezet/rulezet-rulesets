rule sig_20160321_d0f02c75a80597406d1ccb610ab604c0 {
  meta:
    description = "datamaliciousorder - file 20160321_d0f02c75a80597406d1ccb610ab604c0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "835b3edc89bcdb62a3c395b0a68797a559f272aa60ddb8aac0cb15a2468da3a2"

  strings:
    $s1  = "return WScript.CreateObject(dUgVD);" fullword ascii
    $s2  = "var Op = true  , eacj = AOm[7] + AOm[9] + AOm[11];" fullword ascii
    $s3  = "return ttPvibR[0] + ttPvibR[2] + ttPvibR[4] + \".F\" + ttPvibR[7] + ttPvibR[9] + ttPvibR[12] + ttPvibR[14];" fullword ascii
    $s4  = "EZglu.open(xJcIo,coBGW,false);" fullword ascii
    $s5  = "var AOm = (\"2.XMLHTTP rCPSrli lSZBv XML ream St MTzWlsCT AD IrScvvP O iuJp D\").split(\" \");" fullword ascii
    $s6  = "var ttPvibR = Cdwkl(huuUoZkgKv+\" \"+\"System UE ixPXd Obj cvgUlB ect TvjHKEj njhQp\", \" \");" fullword ascii
    $s7  = "return FaT.size;" fullword ascii
    $s8  = "function RzxP(SEtEj) {" fullword ascii
    $s9  = "if (juhIm == 707-507){return true;} else {return false;}" fullword ascii
    $s10 = "return HNhZx.status;" fullword ascii
    $s11 = "function dPWa(vxzNX) {" fullword ascii
    $s12 = "return WgxYCPx(NV,wpRfr[795-789]+wpRfr[888-881]+wpRfr[932-924]);" fullword ascii
    $s13 = "return imQn[gApZNZ[0]];" fullword ascii
    $s14 = "function dPnc(yvJKh) {" fullword ascii
    $s15 = "return ruKiBU.position=148-148;" fullword ascii
    $s16 = "function ONFK(NDSzz,PIriv) {" fullword ascii
    $s17 = "function VgqF(HNhZx) {" fullword ascii
    $s18 = "return new ActiveXObject(QwfMNQ);" fullword ascii
    $s19 = "function TpOUaUQfE(BQdNo) {" fullword ascii
    $s20 = "function reBo(SUYhc) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}