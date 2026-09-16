rule sig_20160311_3cd983cc1cf8a5c424e892fd579daf5d {
  meta:
    description = "datamaliciousorder - file 20160311_3cd983cc1cf8a5c424e892fd579daf5d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fdd188597a22a10c2adbd2cbeee21ab71ad5edab1f9d43d378e924b1ba7b47c3"

  strings:
    $s1  = "return BVXDivX[0] + BVXDivX[2] + BVXDivX[4] + \".F\" + BVXDivX[7] + BVXDivX[9] + BVXDivX[12] + BVXDivX[14];" fullword ascii
    $s2  = "var He = true  , hXJu = dkF[7] + dkF[9] + dkF[11];" fullword ascii
    $s3  = "var BVXDivX = \"Sc fnoKNGd r DwOscvsRv ipting krQPMrH aJV ile CgZTqzLnaYalaG System uo IdBsU Obj LhhVQu ect QyLKYOw\".split(\" " ascii
    $s4  = "var dkF = (\"2.XMLHTTP RhznmCM ReljY XML ream St dDCWUVVY AD mSlCkTc O tkYw D\").split(\" \");" fullword ascii
    $s5  = "FpDSZ.open(MajbS,oHKlt,false);" fullword ascii
    $s6  = "LEG.CreateFolder(gRAB);" fullword ascii
    $s7  = "function TxeIfUXFp(jhuWjTHJwlH) {" fullword ascii
    $s8  = "return new ActiveXObject(AiVMbB);" fullword ascii
    $s9  = "function JmYrOUP(WKqO) {" fullword ascii
    $s10 = "function AArBjjKQ(hPEuV,PiupNp) {" fullword ascii
    $s11 = "function kbGEiGQDH() {" fullword ascii
    $s12 = "var gRAB = yVW+IngReM[0]+IngReM[1];" fullword ascii
    $s13 = "if (U >= ivqcO.length) {break;}" fullword ascii
    $s14 = "function EqpelQUE() {" fullword ascii
    $s15 = "function VTvi(uWszF) {" fullword ascii
    $s16 = "function Zwbo(FpDSZ,oHKlt,MajbS) {" fullword ascii
    $s17 = "function oOcbPgS(ZDAk,whqKG) {" fullword ascii
    $s18 = "vsD = g; break; " fullword ascii
    $s19 = "function PMMDb(GKgPUR) {" fullword ascii
    $s20 = "function CKMV(CDkpn) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}