rule sig_20160310_5af2ba41994407b1c682492d8ca27ffd {
  meta:
    description = "datamaliciousorder - file 20160310_5af2ba41994407b1c682492d8ca27ffd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "352c1d7486ad646e66c49265d5676dad106614f45e6275e40016532f1e06de85"

  strings:
    $s1  = "return ErgGNak[0] + ErgGNak[2] + ErgGNak[4] + \".F\" + ErgGNak[7] + ErgGNak[9] + ErgGNak[12] + ErgGNak[14];" fullword ascii
    $s2  = "var gF = true  , TiFU = jlC[7] + jlC[9] + jlC[11];" fullword ascii
    $s3  = "var jlC = (\"2.XMLHTTP hhhIsze MlKBH XML ream St DnGzOuXe AD beFuqzm O cGik D\").split(\" \");" fullword ascii
    $s4  = "var ErgGNak = \"Sc vagArdh r LlHGBSFxe ipting vCTaTnt gpg ile qmWMmYYoinLsUq System Bj JeMce Obj qptHrk ect QYipCUI\".split(\" " ascii
    $s5  = "oEoSr.open(gEBuk,IZKnC,false);" fullword ascii
    $s6  = "if (UXsaf == 1172-972){return true;} else {return false;}" fullword ascii
    $s7  = "function endQ(pOTuE) {" fullword ascii
    $s8  = "function cZmB(oEoSr,IZKnC,gEBuk) {" fullword ascii
    $s9  = "return TpTD.responseBody;" fullword ascii
    $s10 = "function atMWgZCC(pNU) {" fullword ascii
    $s11 = "return new ActiveXObject(tFLHAj);" fullword ascii
    $s12 = "return tPAOaXG(Ye,RnxDk[994-988]+RnxDk[874-867]+RnxDk[352-344]);" fullword ascii
    $s13 = "function LCeV(YMwNl) {" fullword ascii
    $s14 = "function tPAOaXG(ipSk,cmGHA) {" fullword ascii
    $s15 = "function CBIfuKVGv(IwbNHsbyEhW) {" fullword ascii
    $s16 = "return pNU.size;" fullword ascii
    $s17 = "function loBz(lsJfK,COnzo) {" fullword ascii
    $s18 = "return IpNbNiU" fullword ascii
    $s19 = "function NLcjESqh() {" fullword ascii
    $s20 = "if (pOTuE > 190638-248){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}