rule sig_20160411_608dedb511263581818e8b6390579890 {
  meta:
    description = "datamaliciousorder - file 20160411_608dedb511263581818e8b6390579890.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2fb0e3e8ac543edef2fc2084169b00cd2ad7322d06ddad4492ff7f2e33aa6a14"

  strings:
    $s1  = "var pi = true  , qzdP = jmS[7] + jmS[9] + jmS[11];" fullword ascii
    $s2  = "return VrWXciD[0] + VrWXciD[2] + VrWXciD[4] + \".F\" + VrWXciD[7] + VrWXciD[9] + VrWXciD[12] + VrWXciD[14];" fullword ascii
    $s3  = "HTrN.open(uHWaZ,kOGby,false);" fullword ascii
    $s4  = "var jmS = (\"2.XMLHTTP gbroHcB RUtHd XML ream St nrFqdyYU AD TaFLNSg O Ipdn D\").split(\" \");" fullword ascii
    $s5  = "function OUICzQa(Nwvs) {" fullword ascii
    $s6  = "function Gzda(AFlMe) {" fullword ascii
    $s7  = "if (I >= loOXk.length) {break;}" fullword ascii
    $s8  = "return Nwvs[zZektOl[0]+zZektOl[1]];" fullword ascii
    $s9  = "function FKWzaQfhs(iUBGZvZkDlp) {" fullword ascii
    $s10 = "if (AFlMe == 551-351){return true;} else {return false;}" fullword ascii
    $s11 = "function jarQ(WCzVw,kOGby,uHWaZ) {" fullword ascii
    $s12 = "function SWRt(nJZCH,hsZFO) {" fullword ascii
    $s13 = "return EMw[dXzE[0]](VrhJU);" fullword ascii
    $s14 = "function KEJd(loOXk) {" fullword ascii
    $s15 = "function hBkC(gHSdf) {" fullword ascii
    $s16 = "return xaUyR;" fullword ascii
    $s17 = "return YxepVNe(rX,YDitIF+efQHX[723-715]);" fullword ascii
    $s18 = "function YxepVNe(nxwq,pNPRF) {" fullword ascii
    $s19 = "return ktLuFBz[0];" fullword ascii
    $s20 = "return kqqeuia;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}