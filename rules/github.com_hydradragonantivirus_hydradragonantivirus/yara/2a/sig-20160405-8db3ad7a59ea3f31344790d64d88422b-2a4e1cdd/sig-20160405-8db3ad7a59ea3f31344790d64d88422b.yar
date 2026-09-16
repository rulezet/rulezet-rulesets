rule sig_20160405_8db3ad7a59ea3f31344790d64d88422b {
  meta:
    description = "datamaliciousorder - file 20160405_8db3ad7a59ea3f31344790d64d88422b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "10a90e290f890068b4be9cb7460db1aec9d42fb7f511213ed43c7266e2b31f24"

  strings:
    $s1  = "var NVC = (\"2.XMLHTTP uTvpgYT jDLlU XML ream St DZdzOlIh AD wBJnDJw O DDqr D\").split(\" \");" fullword ascii
    $s2  = "return pnmJVYL[0] + pnmJVYL[2] + pnmJVYL[4] + \".F\" + pnmJVYL[7] + pnmJVYL[9] + pnmJVYL[12] + pnmJVYL[14];" fullword ascii
    $s3  = "var kY = true  , YXqb = NVC[7] + NVC[9] + NVC[11];" fullword ascii
    $s4  = "edVx.open(tXNym,Edrkz,false);" fullword ascii
    $s5  = "function XokV(rdjhX) {" fullword ascii
    $s6  = "function sOdR(eSYcO,AOHAO) {" fullword ascii
    $s7  = "function MRLrWqRul(RtiCS) {" fullword ascii
    $s8  = "function yTGwrW(kKdp,AexzXd) {" fullword ascii
    $s9  = "function UzPd(GAJsf) {" fullword ascii
    $s10 = "function mwTDDp(QjNlZym) {" fullword ascii
    $s11 = "if (rdjhX == 783-583){return true;} else {return false;}" fullword ascii
    $s12 = "return EWFnYvl;" fullword ascii
    $s13 = "function VgEu(upHKc,Edrkz,tXNym) {" fullword ascii
    $s14 = "function XUdK(pGkzS) {" fullword ascii
    $s15 = "if (Q >= pGkzS.length) {break;}" fullword ascii
    $s16 = "function xHbQOUnv(qBy) {" fullword ascii
    $s17 = "function UiVK(KUzpl) {" fullword ascii
    $s18 = "return miLbLPG[0];" fullword ascii
    $s19 = "if(d>=n.length) {break;}" fullword ascii
    $s20 = "return new ActiveXObject(DTFR);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}