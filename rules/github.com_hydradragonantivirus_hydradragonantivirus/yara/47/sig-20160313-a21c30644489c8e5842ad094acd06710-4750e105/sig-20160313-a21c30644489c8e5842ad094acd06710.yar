rule sig_20160313_a21c30644489c8e5842ad094acd06710 {
  meta:
    description = "datamaliciousorder - file 20160313_a21c30644489c8e5842ad094acd06710.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3014503e79f08fd10842e719b180ce92849d193ceec4b203559f6f37b6aed91"

  strings:
    $s1  = "var LQ = true  , cGVK = tZk[7] + tZk[9] + tZk[11];" fullword ascii
    $s2  = "return LuAjzbd[0] + LuAjzbd[2] + LuAjzbd[4] + \".F\" + LuAjzbd[7] + LuAjzbd[9] + LuAjzbd[12] + LuAjzbd[14];" fullword ascii
    $s3  = "dEkMY.open(izSTO,Aqykv,false);" fullword ascii
    $s4  = "var tZk = (\"2.XMLHTTP SoYKLSK yqtPn XML ream St QumIYphP AD DREqwHL O SrhG D\").split(\" \");" fullword ascii
    $s5  = "var LuAjzbd = \"Sc pfBrqQx r ptmXGKpmn ipting cnYeQuI hxk ile cwjHlNHsELXJBt System VL zBlBI Obj rWdVYp ect EmnlLdb\".split(\" " ascii
    $s6  = "return spV.size;" fullword ascii
    $s7  = "function EOlI(pEsPJ) {" fullword ascii
    $s8  = "function wCis(BNkYF) {" fullword ascii
    $s9  = "function PEnW(MqCKg,rEGAp) {" fullword ascii
    $s10 = "function gBMF(UECZS) {" fullword ascii
    $s11 = "return LtlZIlT" fullword ascii
    $s12 = "return AgtVfD.position=317-317;" fullword ascii
    $s13 = "return pEsPJ.status;" fullword ascii
    $s14 = "function qsLb(VyOLx) {" fullword ascii
    $s15 = "function nSTwElCSL(qGQAxtzKZjD) {" fullword ascii
    $s16 = "return new ActiveXObject(YYujhU);" fullword ascii
    $s17 = "FhX = X; break; " fullword ascii
    $s18 = "function qpAq(tdmhi,pALLR) {" fullword ascii
    $s19 = "return vEhc.ExpandEnvironmentStrings(LxEio);" fullword ascii
    $s20 = "function NQZg(dEkMY,Aqykv,izSTO) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}