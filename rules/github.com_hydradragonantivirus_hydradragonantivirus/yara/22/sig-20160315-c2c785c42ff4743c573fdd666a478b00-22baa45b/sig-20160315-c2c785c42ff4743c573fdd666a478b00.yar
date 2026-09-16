rule sig_20160315_c2c785c42ff4743c573fdd666a478b00 {
  meta:
    description = "datamaliciousorder - file 20160315_c2c785c42ff4743c573fdd666a478b00.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "087fbdf4e82d17ee363fcf865553b3aba83459d5d6167c14307869537d825601"

  strings:
    $s1  = "function lhiRCsBhx(XTCMp) {" fullword ascii
    $s2  = "return NOxsmyI[0] + NOxsmyI[2] + NOxsmyI[4] + \".F\" + NOxsmyI[7] + NOxsmyI[9] + NOxsmyI[12] + NOxsmyI[14];" fullword ascii
    $s3  = "var bk = true  , eQZl = LRK[7] + LRK[9] + LRK[11];" fullword ascii
    $s4  = "var NOxsmyI = yOcIV(\"Sc YUhwQoD r zyCYhuxgE ipting nSoKPLI tlB ile UPiiOTNVmJypjW System BG IMaan Obj xyFiJR ect VMASSfj xxyPB" ascii
    $s5  = "var NOxsmyI = yOcIV(\"Sc YUhwQoD r zyCYhuxgE ipting nSoKPLI tlB ile UPiiOTNVmJypjW System BG IMaan Obj xyFiJR ect VMASSfj xxyPB" ascii
    $s6  = "YzFbD.open(TwwrV,NTvxG,false);" fullword ascii
    $s7  = "var LRK = (\"2.XMLHTTP PVhAzco mOxyh XML ream St HPgclMVP AD KItkeZh O RAdK D\").split(\" \");" fullword ascii
    $s8  = "return soFjP;" fullword ascii
    $s9  = "function uDQG(rIsEy) {" fullword ascii
    $s10 = "function SJUKaDQH() {" fullword ascii
    $s11 = "if (a >= XEUyw.length) {break;}" fullword ascii
    $s12 = "function Uwey(tZmuX) {" fullword ascii
    $s13 = "return ObG.size;" fullword ascii
    $s14 = "function aurNs(wFlDOm) {" fullword ascii
    $s15 = "return new ActiveXObject(XxUtpk);" fullword ascii
    $s16 = "function CuLwROGYU(VibHvSdIiEI) {" fullword ascii
    $s17 = "return uMGTG.status;" fullword ascii
    $s18 = "if(Q>=f.length) {break;}" fullword ascii
    $s19 = "function ckZiJPic(ObG) {" fullword ascii
    $s20 = "function yEeA(IWpTZ) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}