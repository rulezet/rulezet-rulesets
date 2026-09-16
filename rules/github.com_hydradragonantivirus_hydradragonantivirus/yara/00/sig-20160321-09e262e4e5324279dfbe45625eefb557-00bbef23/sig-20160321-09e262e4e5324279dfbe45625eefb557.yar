rule sig_20160321_09e262e4e5324279dfbe45625eefb557 {
  meta:
    description = "datamaliciousorder - file 20160321_09e262e4e5324279dfbe45625eefb557.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "372f55a2f2178efa8baed09e30c566da55b22a990978a73b041ca101586bed09"

  strings:
    $s1  = "return WScript.CreateObject(EGXQG);" fullword ascii
    $s2  = "var hA = true  , PIZB = Ntk[7] + Ntk[9] + Ntk[11];" fullword ascii
    $s3  = "return UhvQFmf[0] + UhvQFmf[2] + UhvQFmf[4] + \".F\" + UhvQFmf[7] + UhvQFmf[9] + UhvQFmf[12] + UhvQFmf[14];" fullword ascii
    $s4  = "aqjyT.open(ckoUp,uAgQv,false);" fullword ascii
    $s5  = "var UhvQFmf = Nflgm(jkdzsqsbtK+\" \"+\"System QO WDZoJ Obj jroblY ect dezzGME QGZcj\", \" \");" fullword ascii
    $s6  = "var Ntk = (\"2.XMLHTTP JCpatce yBcNt XML ream St fWFbwJEx AD fYAfvsk O GVqV D\").split(\" \");" fullword ascii
    $s7  = "return SQt.size;" fullword ascii
    $s8  = "function qvIA(ivZLy) {" fullword ascii
    $s9  = "function EKrE(VOHeb,SyxkW) {" fullword ascii
    $s10 = "function URoq(cfzjk) {" fullword ascii
    $s11 = "function rawYhtsc(tMOv) {" fullword ascii
    $s12 = "if (n >= GYESZ.length) {break;}" fullword ascii
    $s13 = "function jWBS(aqjyT,uAgQv,ckoUp) {" fullword ascii
    $s14 = "function Nflgm(nac,LeXEt) {" fullword ascii
    $s15 = "function bmCO(bBQJY) {" fullword ascii
    $s16 = "function eEyacYG(eSwt) {" fullword ascii
    $s17 = "return CStib.status;" fullword ascii
    $s18 = "return FFUh.ExpandEnvironmentStrings(wytah);" fullword ascii
    $s19 = "return new ActiveXObject(oEanMM);" fullword ascii
    $s20 = "function EzgZ(GYESZ) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}