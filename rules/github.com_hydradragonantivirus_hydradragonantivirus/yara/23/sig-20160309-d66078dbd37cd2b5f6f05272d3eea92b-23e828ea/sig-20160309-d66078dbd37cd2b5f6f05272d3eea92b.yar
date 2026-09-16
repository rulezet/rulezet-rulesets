rule sig_20160309_d66078dbd37cd2b5f6f05272d3eea92b {
  meta:
    description = "datamaliciousorder - file 20160309_d66078dbd37cd2b5f6f05272d3eea92b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f38bb607a81a7b4eec67cc74dbe3e4f172e7319d0c3798c0ca47e18ebe30f553"

  strings:
    $s1  = "return tGyANcn[0] + tGyANcn[2] + tGyANcn[4] + \".F\" + tGyANcn[7] + tGyANcn[9] + tGyANcn[12] + tGyANcn[14];" fullword ascii
    $s2  = "var dI = true  , upYy = xTz[7] + xTz[9] + xTz[11];" fullword ascii
    $s3  = "pXsOg.open(MmGzi,kvuki,false);" fullword ascii
    $s4  = "var tGyANcn = \"Sc rGFqidq r AoURvOoJU ipting ekMtCIn MTF ile KdcoAxeWhRxZNx System lp FrgEE Obj ZqXtuX ect jSoVgVk\".split(\" " ascii
    $s5  = "var xTz = (\"2.XMLHTTP kKdVIKJ PxzGs XML ream St TEXWBjeB AD nZhOFzz O DDkP D\").split(\" \");" fullword ascii
    $s6  = "function LUBl(FSSTE,jpFCw) {" fullword ascii
    $s7  = "if (UTbyw == 659-459){return true;} else {return false;}" fullword ascii
    $s8  = "return oJHrw;" fullword ascii
    $s9  = "function bnjmcCdHH(xVoeg,YgckE,CBPGU,qKZr) {" fullword ascii
    $s10 = "return kSqOfQC(CM,ofDOA[733-727]+ofDOA[891-884]+ofDOA[328-320]);" fullword ascii
    $s11 = "return kKEHU.status;" fullword ascii
    $s12 = "QRL = B; break; " fullword ascii
    $s13 = "function rFWH(JEMFV) {" fullword ascii
    $s14 = "return vwzD.ExpandEnvironmentStrings(zZGPk);" fullword ascii
    $s15 = "return new ActiveXObject(BAxnUn);" fullword ascii
    $s16 = "function uRnH(kKEHU) {" fullword ascii
    $s17 = "function Bdaf(whNzJ) {" fullword ascii
    $s18 = "function fZrj(cyYQR,fPchA) {" fullword ascii
    $s19 = "function VYzAt(BAxnUn) {" fullword ascii
    $s20 = "return VQpDoQd" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}