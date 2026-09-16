rule sig_20160323_924041fc255bbdd910a6f5d72adba958 {
  meta:
    description = "datamaliciousorder - file 20160323_924041fc255bbdd910a6f5d72adba958.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00349c6e3ff1050eaccefaa7bc35147f6664fd7af88d2ced57494fb3f07bdf38"

  strings:
    $s1  = "return WScript.CreateObject(PUCrK);" fullword ascii
    $s2  = "return TMiIYSE[0] + TMiIYSE[2] + TMiIYSE[4] + \".F\" + TMiIYSE[7] + TMiIYSE[9] + TMiIYSE[12] + TMiIYSE[14];" fullword ascii
    $s3  = "var Jn = true  , faeA = kqQ[7] + kqQ[9] + kqQ[11];" fullword ascii
    $s4  = "var TMiIYSE = RCeDK(xPhDtoLaLb+\" \"+\"System fn Kkbsk Obj RTeMCn ect esOBFPn ghMZE\", \" \");" fullword ascii
    $s5  = "var kqQ = (\"2.XMLHTTP yelblKI gHWxB XML ream St CSumZmxW AD KrGZeSa O QjrW D\").split(\" \");" fullword ascii
    $s6  = "ejno.open(roUCh,ifLhD,false);" fullword ascii
    $s7  = "function CoLf(CSmVs) {" fullword ascii
    $s8  = "return new ActiveXObject(kPXm);" fullword ascii
    $s9  = "function RCeDK(Bja,WRhJw) {" fullword ascii
    $s10 = "function PcQn(cPxty) {" fullword ascii
    $s11 = "function iZDzZzVI(tMGo) {" fullword ascii
    $s12 = "return Bja.split(WRhJw);" fullword ascii
    $s13 = "return nOhrq.status;" fullword ascii
    $s14 = "function GdPU(bTuPW) {" fullword ascii
    $s15 = "function RiLa(MIqjq,QVral) {" fullword ascii
    $s16 = "function hGPK(nOhrq) {" fullword ascii
    $s17 = "function VElLF(zLsYHm) {" fullword ascii
    $s18 = "function nZhGVRd(MTbD) {" fullword ascii
    $s19 = "return gDydPtM(TK,fjHQb[687-681]+fjHQb[342-335]+fjHQb[580-572]);" fullword ascii
    $s20 = "Plt = R; break; " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}