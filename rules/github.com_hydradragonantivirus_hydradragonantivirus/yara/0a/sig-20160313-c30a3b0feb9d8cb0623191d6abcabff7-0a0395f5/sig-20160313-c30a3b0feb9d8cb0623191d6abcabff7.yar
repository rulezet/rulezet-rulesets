rule sig_20160313_c30a3b0feb9d8cb0623191d6abcabff7 {
  meta:
    description = "datamaliciousorder - file 20160313_c30a3b0feb9d8cb0623191d6abcabff7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e3c3f7d950a3bb41ba5d260418b3c8008b39f551c50b536a46b939d8b735ef01"

  strings:
    $s1  = "var Xk = true  , kuvE = SLb[7] + SLb[9] + SLb[11];" fullword ascii
    $s2  = "return hFRLXGS[0] + hFRLXGS[2] + hFRLXGS[4] + \".F\" + hFRLXGS[7] + hFRLXGS[9] + hFRLXGS[12] + hFRLXGS[14];" fullword ascii
    $s3  = "WOpRT.open(oRDBt,NCGhX,false);" fullword ascii
    $s4  = "var hFRLXGS = \"Sc ZkFmQWr r lecpmLPfS ipting wmvRUSS RuI ile kGEjWQiwlSmYlr System qf ZxrQJ Obj weSsid ect YuspOpS\".split(\" " ascii
    $s5  = "var SLb = (\"2.XMLHTTP eLbSvxR xhELy XML ream St dAHPkfqT AD rConIqG O QOno D\").split(\" \");" fullword ascii
    $s6  = "function cWNn(iFmZP) {" fullword ascii
    $s7  = "function VLRu(dHFuq) {" fullword ascii
    $s8  = "function LIkTv(goHJaJ) {" fullword ascii
    $s9  = "if(c>=m.length) {break;}" fullword ascii
    $s10 = "return ZIQxHej(DC,MZZKR[651-645]+MZZKR[803-796]+MZZKR[203-195]);" fullword ascii
    $s11 = "return lvl.size;" fullword ascii
    $s12 = "if (s >= qWjVL.length) {break;}" fullword ascii
    $s13 = "function PDth(XJaMZ,RvpCg) {" fullword ascii
    $s14 = "return ttgao;" fullword ascii
    $s15 = "function Lrnu(oIcCy) {" fullword ascii
    $s16 = "return new ActiveXObject(goHJaJ);" fullword ascii
    $s17 = "function ZIQxHej(QWGO,nEZgy) {" fullword ascii
    $s18 = "function qPxxuZGR(lvl) {" fullword ascii
    $s19 = "function wSkIy(LClIzp) {" fullword ascii
    $s20 = "return nkTuHbl" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}