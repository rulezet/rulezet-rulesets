rule sig_20160310_a53137d66341f6b068c5784a2cc334a3 {
  meta:
    description = "datamaliciousorder - file 20160310_a53137d66341f6b068c5784a2cc334a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12bdd74d68f74562b1abe440ccd75bbb7cd612898d1132cc187dc4484120e0dd"

  strings:
    $s1  = "var UC = true  , BLqU = KMe[7] + KMe[9] + KMe[11];" fullword ascii
    $s2  = "return jAqRpGx[0] + jAqRpGx[2] + jAqRpGx[4] + \".F\" + jAqRpGx[7] + jAqRpGx[9] + jAqRpGx[12] + jAqRpGx[14];" fullword ascii
    $s3  = "CdOkH.open(hBRJH,uzYBg,false);" fullword ascii
    $s4  = "var KMe = (\"2.XMLHTTP hVqbALO WXxLi XML ream St daFaeGyZ AD vWCnqkV O Cugl D\").split(\" \");" fullword ascii
    $s5  = "var jAqRpGx = \"Sc UBxZMUb r cMANLWEyT ipting npnKllD cir ile ZKudIXMwAjPODP System sl znxin Obj xjkEqm ect DNQSAsk\".split(\" " ascii
    $s6  = "function iKeS(uRbmS) {" fullword ascii
    $s7  = "function qVzDUUzPq(UTJMj,rmJCc,GSsQA,IQgt) {" fullword ascii
    $s8  = "return koLP.responseBody;" fullword ascii
    $s9  = "if (IQJDn == 844-644){return true;} else {return false;}" fullword ascii
    $s10 = "if(k>=l.length) {break;}" fullword ascii
    $s11 = "function dLCR(LnFJF) {" fullword ascii
    $s12 = "function uszgJvN(asJh,FTYUg) {" fullword ascii
    $s13 = "function qZxi(HUVGt) {" fullword ascii
    $s14 = "if (w >= Wtlfr.length) {break;}" fullword ascii
    $s15 = "function mlAghieb(Nugbw,TejqjK) {" fullword ascii
    $s16 = "function CHpM(UxUBw) {" fullword ascii
    $s17 = "function lkeIV(MvIgoo) {" fullword ascii
    $s18 = "return RWg.size;" fullword ascii
    $s19 = "return asJh.ExpandEnvironmentStrings(FTYUg);" fullword ascii
    $s20 = "VMu = k; break; " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}