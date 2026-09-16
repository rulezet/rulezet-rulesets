rule sig_20160308_4ff42d789335d7e0eeafcdb0b131bdf2 {
  meta:
    description = "datamaliciousorder - file 20160308_4ff42d789335d7e0eeafcdb0b131bdf2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d514b57887ca1ab2425dd265af8b166843f4e9076e9f3ce7a478c9889ab3239"

  strings:
    $s1  = "var UkzwHnS = \"Sc RnTpRIg r xbVfFEyeu ipting OjgBhWA OgV ile LgYXYomiXwJAOP System Jy EMiwX Obj Rnfweq ect mIcLwbM\".split(\" " ascii
    $s2  = "return UkzwHnS[0] + UkzwHnS[2] + UkzwHnS[4] + \".F\" + UkzwHnS[7] + UkzwHnS[9] + UkzwHnS[12] + UkzwHnS[14];" fullword ascii
    $s3  = "var Vb = true  , HNqn = cPI[7] + cPI[9] + cPI[11];" fullword ascii
    $s4  = "hxnGM.open(LbroM,uSvDf,false);" fullword ascii
    $s5  = "var cPI = (\"2.XMLHTTP ejWcVoH AAVQs XML ream St EhMwvmju AD aTrIIYS O tUDU D\").split(\" \");" fullword ascii
    $s6  = "if(i>=M.length) {break;}" fullword ascii
    $s7  = "if (JKGIs == 924-724){return true;} else {return false;}" fullword ascii
    $s8  = "if (tHlra > 165238-826){return true;} else {return false;}" fullword ascii
    $s9  = "BIa = i; break; " fullword ascii
    $s10 = "function NxAS(sBJHH) {" fullword ascii
    $s11 = "function ajZpRqyNn(wlvbxzPjSBt) {" fullword ascii
    $s12 = "function FKEc(dqEjo,LNjEX) {" fullword ascii
    $s13 = "return Cuu.size;" fullword ascii
    $s14 = "function TruYU(fyezbW) {" fullword ascii
    $s15 = "function GmrH(sGNBu) {" fullword ascii
    $s16 = "function zxjpePz(niay) {" fullword ascii
    $s17 = "if (g >= ZUSOw.length) {break;}" fullword ascii
    $s18 = "function FZyz(tHlra) {" fullword ascii
    $s19 = "function VtNM(rxxPS) {" fullword ascii
    $s20 = "function ojrkJsrJ(Cuu) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}